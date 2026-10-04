// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Project PolicyShield v2 Authors */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "policyshield.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * ============================================================================
 * PINNED BPF MAP DECLARATIONS
 * ============================================================================
 */

/* 1. Global policy verdicts keyed by cgroup_id */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct policyshield_verdict_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policyshield_verdicts SEC(".maps");

/* 2. Real-time pricing vectors in fixed-point nano-USD */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct pricing_vector);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_pricing_catalog SEC(".maps");

/* 3. Department/tenant budget token buckets and spend limits */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct tenant_budget_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_tenant_budgets SEC(".maps");

/* 4. Per-CPU core live execution burn telemetry (zero false-sharing) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct finops_telemetry_entry);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policyshield_finops SEC(".maps");

/* 5. Lockless ringbuffer streaming drop events and telemetry to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); /* 16 MB ring buffer */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} policyshield_events SEC(".maps");

/* Helper to emit telemetry events to the ringbuffer */
static __always_inline void emit_ringbuf_event(
    __u64 cgroup_id,
    __u32 pid,
    __u32 uid,
    __u32 tenant_id,
    __u32 event_type,
    __u32 verdict,
    __u32 reason_code,
    __u64 estimated_cost,
    __u64 burn_rate,
    const char *comm)
{
    struct policyshield_event *event;

    event = bpf_ringbuf_reserve(&policyshield_events, sizeof(*event), 0);
    if (!event) {
        /* Ringbuffer full or congested; drop telemetry without breaking enforcement */
        return;
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    event->cgroup_id = cgroup_id;
    event->pid = pid;
    event->uid = uid;
    event->tenant_id = tenant_id;
    event->event_type = event_type;
    event->verdict = verdict;
    event->reason_code = reason_code;
    event->estimated_cost_nano_usd = estimated_cost;
    event->current_burn_rate_nano_usd_sec = burn_rate;
    
    if (comm) {
        __builtin_memcpy(event->comm, comm, sizeof(event->comm));
    } else {
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
    }

    bpf_ringbuf_submit(event, 0);
}

/*
 * ============================================================================
 * LSM HOOK: bprm_check_security
 * Intercepts binary execution right before container/process execution.
 * Return 0 to admit, -EPERM (-1) for security violation, -EDQUOT (-122) for FinOps.
 * ============================================================================
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(policyshield_bprm_check, struct linux_binprm *bprm)
{
    __u64 cgroup_id;
    __u64 pid_tgid;
    __u32 pid;
    __u32 uid;
    char comm[16];

    /* Fast path: Obtain current cgroup ID */
    cgroup_id = bpf_get_current_cgroup_id();

    /*
     * 1. FAST-PATH ROOT CGROUP CHECK:
     * Cgroup ID 1 represents the root hierarchy (systemd / host init).
     * Fast-path bypass eliminates any overhead on critical system daemons.
     */
    if (cgroup_id <= 1) {
        return 0;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    pid = (__u32)(pid_tgid >> 32);
    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&comm, sizeof(comm));

    /*
     * 2. LOCKLESS RCU LOOKUP: policyshield_verdicts
     * Lookup current pre-evaluated verdict for this container cgroup.
     * Takes ~15ns under RCU read lock.
     */
    struct policyshield_verdict_entry *verdict_entry;
    verdict_entry = bpf_map_lookup_elem(&policyshield_verdicts, &cgroup_id);

    /* If no entry is registered for this cgroup, permit host process (Fail-Safe) */
    if (!verdict_entry) {
        return 0;
    }

    if (verdict_entry->verdict != VERDICT_ALLOW) {
        emit_ringbuf_event(cgroup_id, pid, uid, verdict_entry->tenant_id,
                           EVENT_TYPE_DROPPED_SECURITY,
                           VERDICT_DENY, verdict_entry->reject_reason ? verdict_entry->reject_reason : EPERM_CODE,
                           0, 0, comm);
        bpf_printk("policyshield_lsm: BLOCKED pid=%d comm=%s cgroup=%llu reason=EPERM\n", pid, comm, cgroup_id);
        return -EPERM_CODE;
    }

    /*
     * 3. ZERO-TRUST SECURITY ENFORCEMENT:
     * Check security flags in the verdict entry.
     * Disallow unauthorized privileged mode or capability escalations.
     */
    if (verdict_entry->security_flags & (SEC_FLAG_PRIVILEGED | SEC_FLAG_HOST_NETWORK | SEC_FLAG_CAP_SYS_ADMIN)) {
        emit_ringbuf_event(cgroup_id, pid, uid, verdict_entry->tenant_id,
                           EVENT_TYPE_DROPPED_SECURITY,
                           VERDICT_DENY, EPERM_CODE, 0, 0, comm);
        bpf_printk("policyshield_lsm: BLOCKED pid=%d comm=%s cgroup=%llu reason=PRIVILEGED\n", pid, comm, cgroup_id);
        return -EPERM_CODE;
    }

    /*
     * 4. REAL-TIME PRE-DISPATCH FINOPS UNIT ECONOMICS CHECK:
     * Lookup current volatile pricing vector and tenant budget.
     */
    __u32 instance_type = verdict_entry->instance_type_id;
    struct pricing_vector *pricing = bpf_map_lookup_elem(&map_pricing_catalog, &instance_type);

    __u32 tenant_id = verdict_entry->tenant_id;
    struct tenant_budget_entry *budget = bpf_map_lookup_elem(&map_tenant_budgets, &tenant_id);

    /* If tenant budget or pricing catalog is configured, enforce strict economic boundaries */
    if (budget && pricing) {
        __u64 spot_ppm = pricing->spot_rate_multiplier_ppm;
        if (spot_ppm == 0) {
            spot_ppm = PPM_SCALE;
        }

        /*
         * Compute Instantaneous Burn Rate:
         * burn_rate = (base_unit_cost * spot_ppm) / PPM_SCALE
         */
        __u64 instantaneous_burn = (pricing->unit_cost_nano_usd_per_sec * spot_ppm) / PPM_SCALE;

        /*
         * Compute Effective Cost Per Transaction (CPT):
         * effective_cpt = (cpt_baseline * spot_ppm) / PPM_SCALE
         */
        __u64 effective_cpt = (pricing->cpt_baseline_nano_usd * spot_ppm) / PPM_SCALE;

        /* Check 4a: Max Allowed CPT Threshold Exceeded */
        __u64 max_cpt = verdict_entry->max_allowed_cpt_nano_usd;
        if (max_cpt > 0 && effective_cpt > max_cpt) {
            emit_ringbuf_event(cgroup_id, pid, uid, tenant_id,
                               EVENT_TYPE_DROPPED_FINOPS,
                               VERDICT_DENY, EDQUOT_CODE,
                               verdict_entry->approved_cost_limit_nano_usd,
                               instantaneous_burn, comm);
            bpf_printk("policyshield_lsm: BLOCKED pid=%d comm=%s cgroup=%llu reason=EDQUOT_CPT\n", pid, comm, cgroup_id);
            return -EDQUOT_CODE;
        }

        /* Check 4b: Department Instantaneous Burn Rate Ceiling Exceeded */
        if (budget->burn_rate_ceiling_nano_usd_sec > 0 &&
            instantaneous_burn > budget->burn_rate_ceiling_nano_usd_sec) {
            emit_ringbuf_event(cgroup_id, pid, uid, tenant_id,
                               EVENT_TYPE_DROPPED_FINOPS,
                               VERDICT_DENY, EDQUOT_CODE,
                               verdict_entry->approved_cost_limit_nano_usd,
                               instantaneous_burn, comm);
            bpf_printk("policyshield_lsm: BLOCKED pid=%d comm=%s cgroup=%llu reason=EDQUOT_BURN\n", pid, comm, cgroup_id);
            return -EDQUOT_CODE;
        }

        /*
         * Check 4c: Budget Ceiling vs Projected Spend:
         * Verify if adding approved_cost_limit exceeds the tenant's hard budget limit.
         */
        __u64 cost_to_commit = verdict_entry->approved_cost_limit_nano_usd;
        __u64 current_spend = budget->accumulated_spend_nano_usd;

        /* Adversarial Audit Fix CHK-BPF-OVERFLOW: Check integer overflow and budget exhaustion */
        if (cost_to_commit > 0 && (current_spend + cost_to_commit < current_spend)) {
            emit_ringbuf_event(cgroup_id, pid, uid, tenant_id,
                               EVENT_TYPE_DROPPED_FINOPS,
                               VERDICT_DENY, EDQUOT_CODE,
                               cost_to_commit, 0, comm);
            return -EDQUOT_CODE;
        }
        if (budget->budget_limit_nano_usd > 0 &&
            (current_spend + cost_to_commit > budget->budget_limit_nano_usd)) {
            emit_ringbuf_event(cgroup_id, pid, uid, tenant_id,
                               EVENT_TYPE_DROPPED_FINOPS,
                               VERDICT_DENY, EDQUOT_CODE,
                               cost_to_commit, instantaneous_burn, comm);
            return -EDQUOT_CODE;
        }

        /*
         * Check 4d: Token Bucket Rate Limiting:
         * Refill token bucket based on elapsed time since last decay.
         */
        __u64 now_ns = bpf_ktime_get_ns();
        __u64 elapsed_ns = now_ns - budget->last_decay_timestamp_ns;
        if (elapsed_ns > 0 && budget->refill_rate_nano_usd_sec > 0) {
            __u64 tokens_to_add = (elapsed_ns * budget->refill_rate_nano_usd_sec) / 1000000000ULL;
            if (tokens_to_add > 0) {
                __sync_fetch_and_add(&budget->token_bucket_balance, tokens_to_add);
                budget->last_decay_timestamp_ns = now_ns;
            }
        }

        /*
         * 5. ATOMIC ADMISSION UPDATE:
         * Commit the approved cost allocation to accumulated spend atomically.
         */
        if (cost_to_commit > 0) {
            __sync_fetch_and_add(&budget->accumulated_spend_nano_usd, cost_to_commit);
        }

        /*
         * 6. PER-CPU TELEMETRY RECORDING:
         * Zero false-sharing per-CPU hash map for core telemetry.
         */
        struct finops_telemetry_entry *finops_stat;
        finops_stat = bpf_map_lookup_elem(&policyshield_finops, &cgroup_id);
        if (finops_stat) {
            finops_stat->invocation_count++;
            finops_stat->live_burn_nano_usd += cost_to_commit;
            finops_stat->last_exec_timestamp_ns = now_ns;
        } else {
            struct finops_telemetry_entry new_stat = {};
            new_stat.invocation_count = 1;
            new_stat.live_burn_nano_usd = cost_to_commit;
            new_stat.last_exec_timestamp_ns = now_ns;
            bpf_map_update_elem(&policyshield_finops, &cgroup_id, &new_stat, BPF_NOEXIST);
        }

        /* Emit admission telemetry event to the ringbuffer */
        emit_ringbuf_event(cgroup_id, pid, uid, tenant_id,
                           EVENT_TYPE_ADMITTED,
                           VERDICT_ALLOW, 0,
                           cost_to_commit, instantaneous_burn, comm);
    } else {
        /* Emit standard admission event when budget/pricing tracking is bypassed */
        emit_ringbuf_event(cgroup_id, pid, uid, verdict_entry->tenant_id,
                           EVENT_TYPE_ADMITTED,
                           VERDICT_ALLOW, 0,
                           verdict_entry->approved_cost_limit_nano_usd, 0, comm);
    }

    /* All security checks passed and FinOps economics verified */
    return 0;
}
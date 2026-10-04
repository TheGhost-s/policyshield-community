#ifndef __POLICYSHIELD_H__
#define __POLICYSHIELD_H__

/* Standard POSIX error numbers used in kernel LSM */
#define EPERM_CODE          1       /* Operation not permitted */
#define EDQUOT_CODE         122     /* Disk/Resource quota exceeded */

/* Verdict states */
#define VERDICT_UNSET       0
#define VERDICT_ALLOW       1
#define VERDICT_DENY        2

/* Security feature flags */
#define SEC_FLAG_PRIVILEGED                 (1U << 0)
#define SEC_FLAG_HOST_NETWORK              (1U << 1)
#define SEC_FLAG_HOST_PID                  (1U << 2)
#define SEC_FLAG_ALLOW_PRIV_ESCALATION      (1U << 3)
#define SEC_FLAG_ROOT_USER                 (1U << 4)
#define SEC_FLAG_CAP_SYS_ADMIN             (1U << 5)

/* Event classification types */
#define EVENT_TYPE_ADMITTED                 1
#define EVENT_TYPE_DROPPED_SECURITY         2
#define EVENT_TYPE_DROPPED_FINOPS           3

/* Pricing category flags */
#define PRICING_FLAG_ON_DEMAND              0
#define PRICING_FLAG_SPOT                   1
#define PRICING_FLAG_RESERVED               2

/* Precision scaling constants */
#define NANO_USD_PER_USD                    1000000000ULL       /* 10^9 nano-USD = $1.00 */
#define PPM_SCALE                           1000000ULL          /* Parts-per-million scale (1.0x = 1,000,000) */
#define SECONDS_PER_HOUR                    3600ULL

/*
 * Struct: policyshield_verdict_entry
 * Pinned map: policyshield_verdicts
 * Key: __u64 cgroup_id
 */
struct policyshield_verdict_entry {
    __u32 verdict;                          /* VERDICT_ALLOW or VERDICT_DENY */
    __u32 reject_reason;                    /* EPERM_CODE or EDQUOT_CODE */
    __u64 approved_cost_limit_nano_usd;     /* Max cost allocation approved by WASM */
    __u64 max_allowed_cpt_nano_usd;         /* Cost per transaction ceiling */
    __u64 eval_timestamp_ns;                /* Monotonic timestamp of evaluation */
    __u32 security_flags;                   /* Bitmask of allowed/detected capabilities */
    __u32 tenant_id;                        /* Department or Tenant Identifier */
    __u32 instance_type_id;                 /* Associated instance/accelerator type */
    __u32 expected_tps;                     /* Expected workload transactions per second */
} __attribute__((aligned(8)));

/*
 * Struct: pricing_vector
 * Pinned map: map_pricing_catalog
 * Key: __u32 instance_type_id
 */
struct pricing_vector {
    __u64 unit_cost_nano_usd_per_sec;       /* Base hardware unit cost per second in nano-USD */
    __u64 cpt_baseline_nano_usd;            /* Baseline CPT at 1.0x spot rate */
    __u32 spot_rate_multiplier_ppm;         /* Spot volatility ratio in PPM (1,000,000 = 1.0x) */
    __u32 pricing_flags;                    /* Spot vs On-Demand flags */
    __u64 last_updated_ns;                  /* Timestamp of asynchronous update */
} __attribute__((aligned(8)));

/*
 * Struct: tenant_budget_entry
 * Pinned map: map_tenant_budgets
 * Key: __u32 tenant_id
 */
struct tenant_budget_entry {
    __u64 budget_limit_nano_usd;            /* Cumulative budget ceiling in nano-USD */
    __u64 accumulated_spend_nano_usd;       /* Atomic cumulative spend */
    __u64 max_allowed_cpt_nano_usd;         /* Strict maximum CPT for this tenant */
    __u64 burn_rate_ceiling_nano_usd_sec;   /* Max instantaneous burn rate (nano-USD/sec) */
    __u64 token_bucket_balance;             /* Token bucket current balance in nano-USD */
    __u64 last_decay_timestamp_ns;          /* Timestamp of last token bucket refill/decay */
    __u64 refill_rate_nano_usd_sec;         /* Token refill rate per second */
} __attribute__((aligned(8)));

/*
 * Struct: finops_telemetry_entry
 * Pinned map: policyshield_finops (PERCPU)
 * Key: __u64 cgroup_id
 */
struct finops_telemetry_entry {
    __u64 cpu_runtime_ns;                   /* Aggregated CPU runtime on this core */
    __u64 live_burn_nano_usd;               /* Live execution cost incurred on this core */
    __u64 invocation_count;                 /* Total process exec admissions on this core */
    __u64 last_exec_timestamp_ns;           /* Monotonic timestamp of last execution */
} __attribute__((aligned(8)));

/*
 * Struct: policyshield_event
 * Pinned map: policyshield_events (RINGBUF)
 */
struct policyshield_event {
    __u64 timestamp_ns;                     /* Timestamp of interception */
    __u64 cgroup_id;                        /* Workload cgroup identifier */
    __u32 pid;                              /* Host PID */
    __u32 uid;                              /* Host UID */
    __u32 tenant_id;                        /* Tenant department ID */
    __u32 event_type;                       /* EVENT_TYPE_* */
    __u32 verdict;                          /* VERDICT_ALLOW or VERDICT_DENY */
    __u32 reason_code;                      /* POSIX return code (0, EPERM, EDQUOT) */
    __u64 estimated_cost_nano_usd;          /* Cost estimate for this invocation */
    __u64 current_burn_rate_nano_usd_sec;   /* Computed burn rate at decision time */
    char comm[16];                          /* Executing process name */
} __attribute__((aligned(8)));

#endif /* __POLICYSHIELD_H__ */
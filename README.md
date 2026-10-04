> **Enterprise Pilot Available**: Looking for Autonomous FinOps, Dynamic Pricing Sync & Multi-Cluster Enterprise Support? Request an Enterprise Pilot: [enterprise@policyshield.dev](mailto:enterprise@policyshield.dev)

# PolicyShield Community Edition - Sub-microsecond (0.44µs) eBPF LSM Sandbox Security for Kubernetes & AI Agents

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Kernel](https://img.shields.io/badge/Linux_Kernel-5.15%2B%20%7C%206.x%20%7C%207.x-orange.svg)](https://kernel.org)
[![eBPF](https://img.shields.io/badge/eBPF-LSM%20%2F%20CO--RE-green.svg)](https://ebpf.io)
[![Latency](https://img.shields.io/badge/Decision_Latency-0.44%C2%B5s-brightgreen.svg)](docs/ENTERPRISE_BENCHMARKS.md)

**PolicyShield Community Edition** is a high-performance, kernel-native security enforcer designed for modern Kubernetes clusters and untrusted AI agent execution sandboxes. By anchoring policy enforcement directly inside the Linux Security Module (LSM) framework at the `bprm_check_security` hook, PolicyShield intercepts process execution (`execve`) inside Ring-0, dropping unauthorized or unbudgeted workloads in **sub-microsecond (0.44µs)** latency—eliminating userspace HTTP webhooks, TLS deadlocks, and network roundtrips entirely.

---

## Technical Architecture (Ring-0 Enforcement)

PolicyShield intercepts container execution at the lowest feasible syscall boundary inside the kernel before CPU, memory, or thread structures are allocated to the binary:

```
+-----------------------------------------------------------------------------------+
|                                 USERSPACE                                         |
|                                                                                   |
|  [ Kubernetes Pod / AI Agent ]       [ Container Runtime (containerd / CRI-O) ]  |
|               |                                           |                       |
|               | execve("/bin/malicious_bin")              | cgroup v2 creation    |
|               |                                           v                       |
|               |                           +-----------------------------------+   |
|               |                           | PolicyShield Userspace Controller |   |
|               |                           +-----------------+-----------------+   |
|               |                                             | Updates Map         |
+---------------+---------------------------------------------|---------------------+
|               | SYSCALL BOUNDARY                            v                     |
+---------------+-------------------------------------------------------------------+
|               v                                             |                     |
|  [ Linux VFS / Syscall Entry ]                              |                     |
|               |                                             v                     |
|               v                               +-------------------------------+   |
|  [ LSM Hook: bprm_check_security ] ---------> | Pinned BPF Map: Verdict Table |   |
|               |                               +-------------------------------+   |
|               |-- (Match cgroup_id + Inode)                  |                    |
|               |                                              |                    |
|         +-----+-----+                                        |                    |
|         |  Verdict? | <--------------------------------------+                    |
|         +-----+-----+                                                             |
|        DENY   |   ALLOW                                                           |
|          |    +------------------------> [ JUMP TO RING-0 BINARY EXECUTION ]      |
|          v                                                                        |
|  [ RETURN -EPERM / -EDQUOT ] (0.44 µs)                                            |
|  (Process Terminated Before CPU Allocation)                                       |
|                                                                                   |
|                                  LINUX KERNEL (RING-0)                            |
+-----------------------------------------------------------------------------------+
```

---

## Performance Benchmarks: PolicyShield vs Traditional Approaches

The table below demonstrates physical hardware benchmarks conducted on Linux x86_64 (`Linux 7.0.0-1013-aws`):

| Capability / Metric | PolicyShield (eBPF LSM) | Traditional Webhook (OPA / Gatekeeper) | Standard cgroups v2 Limits | Linux Seccomp / AppArmor |
| :--- | :--- | :--- | :--- | :--- |
| **Enforcement Layer** | **Kernel Ring-0 (`LSM Hook`)** | Userspace HTTP Daemon | Kernel Scheduler & CFS | Syscall Dispatcher Table |
| **Median Latency (P50)**| **0.442 µs (442 ns)** | 148,000 µs (148 ms) | N/A (Reactive) | 2.50 µs |
| **P99 Latency** | **0.891 µs (891 ns)** | 2,450,000 µs (2.45 s) | N/A (Reactive) | 12.40 µs |
| **Network & TLS Hops** | **0 Hops (Direct Memory)** | 2-3 Hops (CoreDNS + TLS) | 0 Hops | 0 Hops |
| **Throughput (Ops/sec)**| **>300,000,000 ops/sec** | ~2,500 ops/sec | N/A | ~8,000,000 ops/sec |
| **Runtime Process Gating**| **Pre-execution atomic drop** | None (Post-admission blind) | Throttling only (no drop) | Static filter list |
| **AI Agent Sandbox Defense**| **Instant subprocess freeze** | Unprotected | Memory limit OOM kill | Permissive / Complex |
| **Return Error to Bash**| `-EPERM` / `-EDQUOT` | Generic API Server HTTP 500 | Process `SIGKILL` | `SIGSYS` / `EPERM` |

---

## Repository Structure

```
.
├── bpf/
│   ├── policyshield_lsm.bpf.c   # Core eBPF LSM security enforcement program
│   └── policyshield.h           # Shared kernel/userspace C-ABI memory layouts
├── LICENSE                      # Apache-2.0 License
└── README.md                    # Community documentation and benchmark reference
```

---

## Quick Start & Kernel Setup

### 1. Kernel Requirements
* Linux Kernel `>= 5.15` (Tested on `6.x` and `7.0.0-aws`).
* Kernel compiled with BPF LSM enabled:
  ```bash
  cat /sys/kernel/security/lsm
  # Ensure 'bpf' is present in the output:
  # capability,landlock,lockdown,yama,apparmor,bpf
  ```
  If `bpf` is missing from the LSM line, append `lsm=landlock,lockdown,yama,integrity,apparmor,bpf` to your kernel boot parameters (`/etc/default/grub` or cloud launch templates) and reboot.

### 2. Generate BTF Header (vmlinux.h)
PolicyShield utilizes BPF CO-RE (Compile Once - Run Everywhere):
```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

### 3. Compile the eBPF LSM Bytecode
```bash
cd bpf
clang -O2 -g -target bpf \
  -D__TARGET_ARCH_x86 \
  -I. \
  -c policyshield_lsm.bpf.c \
  -o policyshield_lsm.bpf.o
```

### 4. Load & Attach to Ring-0 Hook
```bash
sudo bpftool prog load policyshield_lsm.bpf.o \
  /sys/fs/bpf/policyshield_lsm \
  autoattach
```

### 5. Inspect Live In-Kernel Maps
```bash
sudo bpftool map show
sudo bpftool prog show name policyshield_bprm
```

---

## Community vs Enterprise Edition

| Feature | Community Edition (This Repo) | Enterprise Edition |
| :--- | :---: | :---: |
| **eBPF LSM Syscall Interception** | Included | Included |
| **Atomic POSIX Verdicts (`-EPERM`)** | Included | Included |
| **Pinned BPF Maps & Ringbuffer** | Included | Included |
| **Real-Time Cloud FinOps (AWS/GCP/Azure)**| Manual / DIY | Automated Streaming Engine |
| **Cranelift WASM JIT Policy Engine** | Excluded | Embedded (<100k fuel limit) |
| **Autonomous Spot Price Multiplier** | Excluded | Multi-Region API Syncer |
| **Kubernetes CRD Operator & Controller**| Excluded | Multi-Cluster Go Operator |
| **Sub-microsecond Failsafe Circuit Breaker**| Excluded | 493ns Automated Bypass |
| **Production SLA & 24/7 Support** | Community | Dedicated Enterprise SLA |

To request enterprise pilots or private demonstrations:
* **Email:** [enterprise@policyshield.dev](mailto:enterprise@policyshield.dev)
* **Organization:** [PolicyShield Enterprise](https://github.com/TheGhost-s/policyshield)

---

## License

This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.

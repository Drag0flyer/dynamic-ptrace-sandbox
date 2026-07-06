# Secure Dynamic Linux Sandbox

A lightweight, high-performance, rootless system-level runtime sandbox built with modern C++23 standards. This engine isolates untrusted binaries using Linux Namespaces, custom User/Group identity mappings, and interactive dual-phase hardware interception via `ptrace`. 

It includes a customized, stateful kernel-level system call firewall featuring absolute storage isolation, path normalization, and an on-demand dynamic execution lockdown mechanism designed for malware analysis workflows.

---

## Architectural Overview

The project relies on a highly synchronized, multi-fork supervision model:

1. **The Supervisor (Parent):** Handles user arguments, deploys the isolated Alpine Linux rootfs environment dynamically if missing, provisions ephemeral RAM workspaces, and performs clean unmount operations upon termination.
2. **The Engineer (Active Monitor):** Detaches completely into private Namespaces (`CLONE_NEWNS`, `CLONE_NEWPID`, `CLONE_NEWUTS`, `CLONE_NEWUSER`), hardens critical pseudo-filesystems (masking `/proc/kcore`, remounting `/proc/sys` as read-only), tracks the current working directories of all threads via stateful **Shadow CWD Tracking**, and acts as the active `ptrace` kernel firewall.
3. **The Prisoner (Confined Process):** Requests `PTRACE_TRACEME` tracking, locks itself down inside the jail boundary using `chroot`, drops root execution privileges safely, maps real host identities to containerized root contexts, and drops into an isolated shell.

---

## The Security Audit & Engineering Journey

During development and continuous verification, two critical low-level security bypasses were surfaced and surgically neutralized:

### 1. The Legacy `open(2)` vs Modern `openat(257)` Trap
* **The Vulnerability:** Initial iterations of the firewall strictly monitored `openat` (Syscall 257) for file creation. Security scanning revealed that utilities optimized for space (such as BusyBox tools found in standard Alpine environments) fallback directly to legacy `open` (Syscall 2) primitives under specific conditions.
* **The Mitigation:** The engine was redesigned to map and multiplex register layouts dynamically based on the active syscall ID. For `openat`, it safely parses flags out of `RDX` and paths out of `RSI`. For `open`, it seamlessly intercepts flags out of `RSI` and targets out of `RDI`.

### 2. Relational Path Escape (`Shadow CWD Tracking`)
* **The Vulnerability:** Malicious programs can attempt to slip past a naive string whitelist by executing file system operations via relative path configurations (e.g., `touch ../../etc/file`).
* **The Mitigation:** The Engineer implements real-time execution state tracking. It intercepts successful `chdir` (Syscall 80) modifications and state inheritances on process branching (`fork`/`clone`). Paths are fed through `std::filesystem::path::lexically_normal()` at the entry phase, ensuring all paths are evaluated in their absolute canonical forms before access evaluation.

---

## Key Capabilities

* **Modern C++23 Implementation:** Leverages compile-time type evaluation (`constexpr`), type-safe OS failure handling (`std::expected`), native views (`std::string_view`), boundaries optimization (`std::span`), and rapid C++23 console output (`std::println`).
* **Zero-Allocation Host Protection:** Evaluates process memory layout directly using native kernel peering (`PTRACE_PEEKDATA`) without modifying or allocations on the heap.
* **Amnesic RAM Workspace:** Passing the `--ephemeral` flag commands `std::filesystem` to duplicate the reference distribution entirely into volatile memory, leaving the physical host drive completely untouched.
* **Dynamic Kernel Lockdown:** Allows users to interactively transition from a safe provision phase (installing debugging tools, dependencies, or compilers) to a zero-trust quarantine phase. Running `touch /tmp/lockdown` signals the hypervisor to instantly revoke storage writing capabilities and block outgoing socket creation (`AF_INET`/`AF_INET6`) on the fly.

---

## Project Structure

```text
projet_sandbox/
├── .clangd              # LSP flag configurations (-std=c++23)
├── CMakeLists.txt       # Unified build directives
├── rootfs/              # Local reference Alpine Linux distribution 
├── src/
│   └── main.cpp         # Main C++ Engine source code
└── build/               # Binary build target generation directory
```

---

## Compilation & Quick Start

Ensure you have a modern compiler compliant with C++23 standards (GCC 13+ or Clang 17+) and CMake installed on your Linux machine.

### 1. Build the Project
```bash
mkdir -p build && cd build
cmake ..
cmake --build .
```

### 2. Launch with Maximum Sandbox Isolation (Default)
By default, storage writes are restricted entirely to `/tmp`, network socket mapping is cut off, and any attempt to modify permissions (`chmod`) is immediately dropped:
```bash
./projet_sandbox
```

### 3. Launching in Provisioning & Dynamic Lockdown Mode
If you need to load testing dependencies or analyze network activity before locking down the process:
```bash
./projet_sandbox --ephemeral --allow-write --allow-net
```
*Your console banner will notify you that the dynamic firewall is armed and ready:*
```text
[Supervisor] Network Security (--allow-net)   : ALLOWED
[Supervisor] Privilege Escalation (--allow-chmod) : BLOCKED
[Supervisor] Storage Security (--allow-write) : UNRESTRICTED (DANGEROUS)
[Supervisor] Execution Mode (--ephemeral)   : ENABLED (RAMDISK volatile)
[Supervisor] Targeted Rootfs Path             : ../rootfs
[Supervisor] Dynamic Lockdown Mode            : READY (Run 'touch /tmp/lockdown' inside to seal)
```

Inside the isolated prompt, install your tools via the internet:
```bash
/ $ apk add python3
```
Once you are ready to evaluate the untrusted binary, execute the seal trigger:
```bash
/ $ touch /tmp/lockdown
[SYSTEM LOCKDOWN] Dynamic trigger detected! Sealing sandbox envelope. Network and Storage privileges are now REVOKED.
```
Any subsequent storage modifications outside `/tmp` or downstream outgoing socket initializations will be injected with an architectural fault (`-EPERM`) code, outputting a clear security alert on your host logging screen.

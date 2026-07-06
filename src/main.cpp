#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>
#include <iostream>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <filesystem>
#include <cstdlib>
#include <sys/user.h>
#include <fstream>
#include <fcntl.h>

#include <print>
#include <expected>
#include <string_view>
#include <system_error>
#include <vector>
#include <cerrno>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <span>

// =========================================================================
// === SYSTEM PROGRAMMING SAFE HELPERS ===
// =========================================================================

std::expected<void, std::error_code> safe_unshare(int flags) noexcept {
    if (::unshare(flags) == -1) {
        return std::unexpected(std::error_code(errno, std::generic_category()));
    }
    return {};
}

std::expected<pid_t, std::error_code> safe_fork() noexcept {
    pid_t pid = ::fork();
    if (pid == -1) {
        return std::unexpected(std::error_code(errno, std::generic_category()));
    }
    return pid;
}

std::expected<void, std::error_code> safe_mount(
    std::string_view source,
    std::string_view target,
    std::string_view fstype,
    unsigned long flags,
    std::nullptr_t data = nullptr) noexcept {

    if (::mount(source.data(), target.data(), fstype.data(), flags, data) == -1) {
        return std::unexpected(std::error_code(errno, std::generic_category()));
    }
    return {};
}

std::expected<void, std::error_code> safe_chroot(std::string_view path) noexcept {
    if (::chroot(path.data()) == -1) {
        return std::unexpected(std::error_code(errno, std::generic_category()));
    }
    if (::chdir("/") == -1) {
        return std::unexpected(std::error_code(errno, std::generic_category()));
    }
    return {};
}

std::expected<void, std::error_code> safe_map_users() noexcept {
    uid_t real_uid = ::getuid();
    gid_t real_gid = ::getgid();

    std::ofstream uid_file("/proc/self/uid_map");
    if (!uid_file) return std::unexpected(std::error_code(errno, std::generic_category()));
    uid_file << std::format("0 {} 1\n", real_uid);
    uid_file.close();

    std::ofstream deny_file("/proc/self/setgroups");
    if (deny_file) {
        deny_file << "deny";
        deny_file.close();
    }

    std::ofstream gid_file("/proc/self/gid_map");
    if (!gid_file) return std::unexpected(std::error_code(errno, std::generic_category()));
    gid_file << std::format("0 {} 1\n", real_gid);
    gid_file.close();

    return {};
}

std::string read_ram_string(pid_t pid, uint64_t address) {
    std::string result;
    size_t read_bytes = 0;
    constexpr size_t MAX_LENGTH = 512;

    while (read_bytes < MAX_LENGTH) {
        long word = ::ptrace(PTRACE_PEEKDATA, pid, address + read_bytes, nullptr);
        if (word == -1 && errno != 0) break;

        auto* bytes = reinterpret_cast<char*>(&word);
        for (size_t i = 0; i < sizeof(long); ++i) {
            if (bytes[i] == '\0') return result;
            result += bytes[i];
        }
        read_bytes += sizeof(long);
    }
    return result;
}

// =========================================================================
// === CORE STRUCTURES & MAIN EXECUTABLE ===
// =========================================================================

struct SandboxConfig {
    std::string rootfs_path = "../rootfs";
    bool block_network = true;
    bool block_chmod = true;
    bool block_write = true;
    bool ephemeral_mode = false;
};

int main(int argc, char* argv[]) {
    SandboxConfig config;

    auto args = std::span(argv, argc);
    for (const auto* arg_ptr : args.subspan(1)) {
        std::string_view arg(arg_ptr);

        if (arg == "--allow-net")          config.block_network = false;
        else if (arg == "--allow-chmod")   config.block_chmod = false;
        else if (arg == "--allow-write")   config.block_write = false;
        else if (arg == "--ephemeral")     config.ephemeral_mode = true;
        else                               config.rootfs_path = arg;
    }

    std::println("--- Launching Secure Dynamic Sandbox ---");
    std::println("[Supervisor] Network Security (--allow-net)   : {}", config.block_network ? "BLOCKED" : "ALLOWED");
    std::println("[Supervisor] Privilege Escalation (--allow-chmod) : {}", config.block_chmod ? "BLOCKED" : "ALLOWED");
    std::println("[Supervisor] Storage Security (--allow-write) : {}", config.block_write ? "STRICT WHITELIST (/tmp)" : "UNRESTRICTED (DANGEROUS)");
    std::println("[Supervisor] Execution Mode (--ephemeral)   : {}", config.ephemeral_mode ? "ENABLED (RAMDISK volatile)" : "DISABLED (PERSISTENT SSD)");
    std::println("[Supervisor] Targeted Rootfs Path             : {}", config.rootfs_path);

    if (!config.block_write || !config.block_network) {
        std::println("[Supervisor] Dynamic Lockdown Mode            : READY (Run 'touch /tmp/lockdown' inside to seal)");
    }

    std::filesystem::path rfs_dir(config.rootfs_path);
    if (!config.ephemeral_mode && (!std::filesystem::exists(rfs_dir) || std::filesystem::is_empty(rfs_dir))) {
        std::println("[Supervisor] Rootfs missing or empty. Deploying standard Alpine Linux distribution...");
        std::filesystem::create_directories(rfs_dir);

        std::string cmd = std::format(
            "VERSION=$(curl -sSL https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/latest-releases.yaml "
            "| grep -o 'alpine-minirootfs-[0-9.]*\\(-rc[0-9]\\)\\?-x86_64\\.tar\\.gz' | head -n 1) && "
            "curl -sSL https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/\"$VERSION\" "
            "| tar -xz -C {}",
            config.rootfs_path
        );

        if (std::system(cmd.c_str()) != 0) {
            std::println(std::cerr, "[Supervisor] Critical Error: Failed to download and extract Alpine rootfs.");
            std::filesystem::remove_all(rfs_dir);
            return 1;
        }
        std::println("[Supervisor] Alpine Linux successfully deployed to {}.", config.rootfs_path);
    }

    if (auto res = safe_unshare(CLONE_NEWUTS | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS); !res) {
        std::println(std::cerr, "[Supervisor] Critical unshare failure: {}", res.error().message());
        return 1;
    }

    if (auto res = safe_map_users(); !res) {
        std::println(std::cerr, "[Supervisor] Critical identity mapping failure: {}", res.error().message());
        return 1;
    }

    if (auto fork1_res = safe_fork(); !fork1_res) {
        std::println(std::cerr, "[Supervisor] Initial fork failure: {}", fork1_res.error().message());
        return 1;
    } else if (*fork1_res > 0) {
        ::waitpid(*fork1_res, nullptr, 0);
        std::println("--- Supervisor successfully closed the sandbox environment ---");
        return 0;
    }

    // =========================================================================
    // === FIRST CHILD: The Engineer (Sandbox Engine & Active Supervisor) ===
    // =========================================================================

    if (auto res = safe_mount("", "/", "", MS_REC | MS_PRIVATE); !res) {
        std::println(std::cerr, "[Engineer] Failed to privatize filesystem mounts: {}", res.error().message());
        ::_exit(1);
    }

    std::string ram_workspace;
    if (config.ephemeral_mode) {
        ram_workspace = std::format("/tmp/sandbox_workspace_{}", ::getpid());
        std::error_code ec;
        std::filesystem::create_directories(ram_workspace, ec);

        std::filesystem::copy(config.rootfs_path, ram_workspace, std::filesystem::copy_options::recursive, ec);
        if (ec) {
            std::println(std::cerr, "[Engineer] Critical Error: Failed to clone rootfs to RAM space natively: {}", ec.message());
            std::filesystem::remove_all(ram_workspace, ec);
            ::_exit(1);
        }

        config.rootfs_path = ram_workspace;
        std::println("[Engineer] Ephemeral workspace successfully cloned to RAM.");
    }

    if (!config.block_network) {
        std::string resolv_path = config.rootfs_path + "/etc/resolv.conf";
        std::ofstream resolv_file(resolv_path);
        if (resolv_file) {
            resolv_file << "nameserver 8.8.8.8\n";
            resolv_file.close();
        }
    }

    std::string proc_target = config.rootfs_path + "/proc";
    if (auto res = safe_mount("proc", proc_target, "proc", 0); !res) {
        std::println(std::cerr, "[Engineer] Failed to mount isolated /proc: {}", res.error().message());
        ::_exit(1);
    }

    const std::vector<std::string> masked_paths = {
        "/proc/kcore", "/proc/sysrq-trigger", "/proc/latency_stats", "/proc/acpi", "/proc/asound"
    };

    for (const auto& path : masked_paths) {
        std::string full_target = config.rootfs_path + path;
        if (std::filesystem::exists(full_target)) {
            if (std::filesystem::is_directory(full_target)) {
                if (auto res = safe_mount("tmpfs", full_target, "tmpfs", MS_RDONLY); !res) {
                    std::println(std::cerr, "[Engineer] Masking failed for directory {}: {}", path, res.error().message());
                    ::_exit(1);
                }
            } else {
                if (auto res = safe_mount("/dev/null", full_target, "", MS_BIND); !res) {
                    std::println(std::cerr, "[Engineer] Masking failed for file {}: {}", path, res.error().message());
                    ::_exit(1);
                }
            }
        }
    }

    std::string sys_target = config.rootfs_path + "/proc/sys";
    if (std::filesystem::exists(sys_target)) {
        if (auto res = safe_mount(sys_target, sys_target, "", MS_BIND); !res) {
            std::println(std::cerr, "[Engineer] Failed to bind-mount /proc/sys: {}", res.error().message());
            ::_exit(1);
        }
        if (auto res = safe_mount("", sys_target, "", MS_BIND | MS_REMOUNT | MS_RDONLY); !res) {
            std::println(std::cerr, "[Engineer] Failed to harden /proc/sys to Read-Only: {}", res.error().message());
            ::_exit(1);
        }
    }

    if (auto fork2_res = safe_fork(); !fork2_res) {
        std::println(std::cerr, "[Engineer] Secondary fork failure: {}", fork2_res.error().message());
        ::_exit(1);
    } else if (*fork2_res > 0) {
        pid_t prisoner_pid = *fork2_res;
        int status;

        ::waitpid(prisoner_pid, &status, 0);

        ::ptrace(PTRACE_SETOPTIONS, prisoner_pid, nullptr,
                 PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);

        std::println("[Engineer] Ptrace monitoring sub-engine engaged on PID {}. Awaiting system calls...", prisoner_pid);

        ::ptrace(PTRACE_SYSCALL, prisoner_pid, nullptr, nullptr);

        std::unordered_set<pid_t> blocked_pids;
        std::unordered_set<pid_t> initialised_pids;
        std::unordered_map<pid_t, std::filesystem::path> shadow_cwd;
        std::unordered_map<pid_t, std::string> pending_chdir;

        int signal_to_forward = 0;

        while (true) {
            pid_t current_pid = ::waitpid(-1, &status, 0);
            if (current_pid == -1) {
                if (errno == ECHILD) break;
                continue;
            }

            signal_to_forward = 0;

            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                blocked_pids.erase(current_pid);
                shadow_cwd.erase(current_pid);
                pending_chdir.erase(current_pid);
                initialised_pids.erase(current_pid);
                if (current_pid == prisoner_pid) {
                    std::println("[Engineer] Main prisoner process exited the sandbox.");
                    break;
                }
                continue;
            }

            if (WIFSTOPPED(status)) {
                int sig = WSTOPSIG(status);

                if (sig & 0x80) {
                    struct user_regs_struct regs;
                    if (::ptrace(PTRACE_GETREGS, current_pid, nullptr, &regs) >= 0) {

                        bool is_entry_phase = (static_cast<int64_t>(regs.rax) == -ENOSYS);

                        if (is_entry_phase) {
                            // --- FIREWALL ENTRY FILTERING ---

                            if (regs.orig_rax == 80) { // chdir
                                pending_chdir[current_pid] = read_ram_string(current_pid, regs.rdi);
                            }
                            else if (regs.orig_rax == 41 && config.block_network) { // socket
                                uint64_t domain = regs.rdi;
                                if (domain == 2 || domain == 10) { // AF_INET / AF_INET6
                                    std::println("\n[FIREWALL] SECURITY ALERT: Outbound network socket creation blocked! [PID: {}]", current_pid);
                                    regs.orig_rax = -1;
                                    ::ptrace(PTRACE_SETREGS, current_pid, nullptr, &regs);
                                    blocked_pids.insert(current_pid);
                                }
                            }
                            else {
                                // --- CHIRURGICAL FILE SYSTEM FIREWALL (open + openat) ---
                                bool is_direct_mutator = (regs.orig_rax == 83 || regs.orig_rax == 258 ||
                                                          regs.orig_rax == 84 || regs.orig_rax == 87  ||
                                                          regs.orig_rax == 263);

                                bool is_open = (regs.orig_rax == 2);
                                bool is_openat = (regs.orig_rax == 257);
                                bool attempts_write_or_create = false;

                                if (is_open) {
                                    uint64_t flags = regs.rsi;
                                    uint64_t mode = flags & O_ACCMODE;
                                    if ((flags & O_CREAT) || mode == O_WRONLY || mode == O_RDWR) {
                                        attempts_write_or_create = true;
                                    }
                                }
                                else if (is_openat) {
                                    uint64_t flags = regs.rdx;
                                    uint64_t mode = flags & O_ACCMODE;
                                    if ((flags & O_CREAT) || mode == O_WRONLY || mode == O_RDWR) {
                                        attempts_write_or_create = true;
                                    }
                                }

                                if (is_direct_mutator || attempts_write_or_create) {
                                    bool uses_rdi = (regs.orig_rax == 2 || regs.orig_rax == 83 || regs.orig_rax == 84 || regs.orig_rax == 87);
                                    std::string raw_target = uses_rdi
                                        ? read_ram_string(current_pid, regs.rdi)
                                        : read_ram_string(current_pid, regs.rsi);

                                    std::filesystem::path internal_path = raw_target.starts_with("/")
                                        ? std::filesystem::path(raw_target)
                                        : (shadow_cwd[current_pid] / raw_target);

                                    internal_path = internal_path.lexically_normal();
                                    std::string path_str = internal_path.string();

                                    // DYNAMIC RUNTIME LOCKDOWN TRIGGER
                                    if (path_str == "/tmp/lockdown") {
                                        config.block_write = true;
                                        config.block_network = true;
                                        std::println("\n[SYSTEM LOCKDOWN] Dynamic trigger detected! Sealing sandbox envelope. Network and Storage privileges are now REVOKED.");
                                    }

                                    if (config.block_write) {
                                        bool is_whitelisted = path_str.starts_with("/tmp") || path_str.starts_with("/dev/");

                                        if (raw_target.empty() || path_str == "/") {
                                            is_whitelisted = true;
                                        }

                                        if (!is_whitelisted) {
                                            std::println("\n[FIREWALL] SECURITY ALERT: Write/Create/Delete operation denied outside /tmp ({}) [PID: {}]", path_str, current_pid);
                                            regs.orig_rax = -1;
                                            ::ptrace(PTRACE_SETREGS, current_pid, nullptr, &regs);
                                            blocked_pids.insert(current_pid);
                                        }
                                    }
                                }
                                else if (regs.orig_rax == 90 && config.block_chmod) { // chmod
                                    std::string target_file = read_ram_string(current_pid, regs.rdi);
                                    std::println("\n[FIREWALL] SECURITY ALERT: Target permission alteration blocked on: {} [PID: {}]", target_file, current_pid);
                                    regs.orig_rax = -1;
                                    ::ptrace(PTRACE_SETREGS, current_pid, nullptr, &regs);
                                    blocked_pids.insert(current_pid);
                                }
                                else if (regs.orig_rax == 59) { // execve
                                    std::string binary_path = read_ram_string(current_pid, regs.rdi);
                                    std::println("[TRACING] Executing subprocess descriptor: {} [PID: {}]", binary_path, current_pid);
                                }
                            }
                        }
                        else {
                            if (blocked_pids.contains(current_pid)) {
                                regs.rax = -EPERM;
                                ::ptrace(PTRACE_SETREGS, current_pid, nullptr, &regs);
                                blocked_pids.erase(current_pid);
                            }
                            else if (regs.orig_rax == 80 && static_cast<int64_t>(regs.rax) == 0) {
                                std::string dest = pending_chdir[current_pid];
                                std::filesystem::path new_cwd = dest.starts_with("/")
                                    ? std::filesystem::path(dest)
                                    : (shadow_cwd[current_pid] / dest);

                                shadow_cwd[current_pid] = new_cwd.lexically_normal();
                                pending_chdir.erase(current_pid);
                            }
                            else if ((regs.orig_rax == 56 || regs.orig_rax == 57 || regs.orig_rax == 58) && static_cast<int64_t>(regs.rax) > 0) {
                                pid_t child_pid = static_cast<pid_t>(regs.rax);
                                shadow_cwd[child_pid] = shadow_cwd[current_pid];
                            }
                        }
                    }
                }
                else {
                    if (sig == SIGSTOP && !initialised_pids.contains(current_pid)) {
                        initialised_pids.insert(current_pid);
                        if (!shadow_cwd.contains(current_pid)) {
                            shadow_cwd[current_pid] = "/";
                        }
                        signal_to_forward = 0;
                    } else if (sig != SIGTRAP) {
                        signal_to_forward = sig;
                    }
                }
            }

            ::ptrace(PTRACE_SYSCALL, current_pid, nullptr, reinterpret_cast<void*>(signal_to_forward));
        }

        // =========================================================================
        // === SURGICAL CLEANUP AND RESOURCE RELEASE (SILENT) ===
        // =========================================================================
        std::string sys_cleanup = std::format("{}/proc/sys", config.rootfs_path);
        ::umount(sys_cleanup.c_str());

        for (auto it = masked_paths.rbegin(); it != masked_paths.rend(); ++it) {
            std::string full_target = config.rootfs_path + *it;
            if (std::filesystem::exists(full_target)) {
                ::umount(full_target.c_str());
            }
        }

        std::string proc_cleanup = std::format("{}/proc", config.rootfs_path);
        ::umount(proc_cleanup.c_str());

        if (config.ephemeral_mode && !ram_workspace.empty()) {
            std::error_code ec;
            std::filesystem::remove_all(ram_workspace, ec);
        }

        ::_exit(0);
    }

    // =========================================================================
    // === SECOND CHILD: The Prisoner (Confined Sandbox Environment) ===
    // =========================================================================

    if (::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
        std::println(std::cerr, "[Prisoner] Fatal: Failed to initialize PTRACE_TRACEME context mapping.");
        ::_exit(1);
    }

    ::raise(SIGSTOP);

    if (auto res = safe_chroot(config.rootfs_path); !res) {
        std::println(std::cerr, "[Prisoner] Fatal: Jail boundary lock down failed: {}", res.error().message());
        ::_exit(1);
    }

    ::setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin", 1);
    ::setenv("HOME", "/root", 1);
    ::setenv("HISTFILE", "", 1);

    ::execl("/bin/sh", "sh", nullptr);
    ::_exit(1);
}

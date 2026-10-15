//! Install confinement before creating any runtime/worker threads.
use anyhow::Result;

#[cfg(not(target_os = "linux"))]
pub fn install() -> Result<()> {
    anyhow::bail!("Kerbin requires Linux with Landlock ABI v3 and seccomp")
}

#[cfg(target_os = "linux")]
pub fn install() -> Result<()> {
    linux::install()
}

#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{Context, Result, ensure};
    use landlock::{
        ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus,
    };
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule,
    };
    use std::{collections::BTreeMap, fs, io};

    pub fn install() -> Result<()> {
        // Landlock v3 is per-thread. Refuse a startup ordering regression that
        // would leave existing threads unconfined; future threads inherit it.
        ensure!(
            fs::read_dir("/proc/self/task")?.count() == 1,
            "Sandbox must be installed before any threads start"
        );
        let filters = filters()?;
        // Drop inherited file/socket handles except stdin/stdout/stderr. Landlock
        // cannot revoke access through descriptors opened before confinement.
        // SAFETY: single-threaded startup, with all certificate file handles closed.
        let result = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) };
        ensure!(
            result == 0,
            "Close inherited descriptors: {}",
            io::Error::last_os_error()
        );
        let mut ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI::V3))?
            .create()
            .context("Create Landlock ruleset (Linux 6.2+ with Landlock enabled required)")?;
        // Hickory reads these files directly and uses TCP/UDP DNS. No libc NSS
        // plugins, Unix domain sockets, home directories, or library trees needed.
        for path in ["/etc/resolv.conf", "/etc/hosts", "/dev/urandom"] {
            match PathFd::new(path) {
                Ok(fd) => {
                    ruleset = ruleset.add_rule(PathBeneath::new(fd, AccessFs::ReadFile))?;
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("Open sandbox read allowance: {path}"));
                }
            }
        }
        let status = ruleset.restrict_self().context("Enforce Landlock")?;
        ensure!(
            status.ruleset == RulesetStatus::FullyEnforced && status.no_new_privs,
            "Landlock restrictions were not fully enforced"
        );
        // Both filters use TSYNC; all later threads inherit both filters.
        for filter in filters {
            seccompiler::apply_filter_all_threads(&filter).context("Enforce seccomp")?;
        }
        Ok(())
    }

    fn condition(arg: u8, op: SeccompCmpOp, value: u64) -> Result<SeccompCondition> {
        Ok(SeccompCondition::new(
            arg,
            SeccompCmpArgLen::Dword,
            op,
            value,
        )?)
    }
    fn rule(conditions: Vec<SeccompCondition>) -> Result<SeccompRule> {
        Ok(SeccompRule::new(conditions)?)
    }

    fn filters() -> Result<Vec<BpfProgram>> {
        let arch = std::env::consts::ARCH.try_into()?;
        // glibc falls back to clone when clone3 returns ENOSYS. clone3's flags
        // are behind a pointer and cannot be safely inspected by classic BPF.
        let clone3 = SeccompFilter::new(
            BTreeMap::from([(libc::SYS_clone3, vec![])]),
            SeccompAction::Allow,
            SeccompAction::Errno(libc::ENOSYS as u32),
            arch,
        )?
        .try_into()?;
        let allowed = [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_readv,
            libc::SYS_writev,
            libc::SYS_pread64,
            libc::SYS_close,
            libc::SYS_fstat,
            libc::SYS_newfstatat,
            libc::SYS_statx,
            libc::SYS_lseek,
            libc::SYS_fcntl,
            libc::SYS_munmap,
            libc::SYS_mremap,
            libc::SYS_brk,
            libc::SYS_madvise,
            libc::SYS_futex,
            libc::SYS_set_robust_list,
            libc::SYS_rseq,
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_sigaltstack,
            libc::SYS_clock_gettime,
            libc::SYS_clock_nanosleep,
            libc::SYS_nanosleep,
            libc::SYS_sched_yield,
            libc::SYS_sched_getaffinity,
            libc::SYS_getpid,
            libc::SYS_gettid,
            libc::SYS_getuid,
            libc::SYS_geteuid,
            libc::SYS_getgid,
            libc::SYS_getegid,
            libc::SYS_uname,
            libc::SYS_getrandom,
            libc::SYS_restart_syscall,
            libc::SYS_exit,
            libc::SYS_exit_group,
            libc::SYS_eventfd2,
            libc::SYS_epoll_create1,
            libc::SYS_epoll_ctl,
            libc::SYS_epoll_pwait,
            libc::SYS_epoll_pwait2,
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept4,
            libc::SYS_getsockname,
            libc::SYS_getpeername,
            libc::SYS_getsockopt,
            libc::SYS_setsockopt,
            libc::SYS_sendto,
            libc::SYS_recvfrom,
            libc::SYS_sendmsg,
            libc::SYS_recvmsg,
            libc::SYS_sendmmsg,
            libc::SYS_recvmmsg,
            libc::SYS_shutdown,
            libc::SYS_clone3, // Denied by the separate ENOSYS filter above.
        ];
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = allowed
            .into_iter()
            .map(|syscall| (syscall, vec![]))
            .collect();
        #[cfg(target_arch = "x86_64")]
        for syscall in [
            libc::SYS_epoll_wait,
            libc::SYS_poll,
            libc::SYS_select,
            libc::SYS_getrlimit,
            libc::SYS_arch_prctl,
        ] {
            rules.insert(syscall, vec![]);
        }
        rules.insert(
            libc::SYS_prlimit64,
            vec![rule(vec![
                condition(0, SeccompCmpOp::Eq, 0)?,
                SeccompCondition::new(2, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, 0)?,
            ])?],
        );
        rules.insert(libc::SYS_ppoll, vec![]);
        rules.insert(libc::SYS_pselect6, vec![]);
        // No executable anonymous mappings or writable-to-executable transitions.
        for syscall in [libc::SYS_mmap, libc::SYS_mprotect] {
            rules.insert(
                syscall,
                vec![rule(vec![condition(
                    2,
                    SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
                    0,
                )?])?],
            );
        }
        let required = (libc::CLONE_VM | libc::CLONE_SIGHAND | libc::CLONE_THREAD) as u64;
        let thread_flags = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM
            | libc::CLONE_SETTLS
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID
            | libc::CLONE_CHILD_SETTID) as u32;
        rules.insert(
            libc::SYS_clone,
            vec![rule(vec![
                SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Qword,
                    SeccompCmpOp::MaskedEq(required),
                    required,
                )?,
                SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Qword,
                    SeccompCmpOp::MaskedEq(!(thread_flags as u64)),
                    0,
                )?,
            ])?],
        );
        let mut socket_rules = Vec::new();
        for domain in [libc::AF_INET, libc::AF_INET6] {
            for (kind, protocol) in [
                (libc::SOCK_STREAM, libc::IPPROTO_TCP),
                (libc::SOCK_DGRAM, libc::IPPROTO_UDP),
            ] {
                for protocol in [0, protocol] {
                    socket_rules.push(rule(vec![
                        condition(0, SeccompCmpOp::Eq, domain as u64)?,
                        condition(
                            1,
                            SeccompCmpOp::MaskedEq(
                                (!(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as u32) as u64,
                            ),
                            kind as u64,
                        )?,
                        condition(2, SeccompCmpOp::Eq, protocol as u64)?,
                    ])?);
                }
            }
        }
        rules.insert(libc::SYS_socket, socket_rules);
        // Tokio uses an internal Unix socket pair for signal notification.
        // socketpair cannot connect to filesystem/abstract Unix socket endpoints.
        rules.insert(
            libc::SYS_socketpair,
            vec![rule(vec![
                condition(0, SeccompCmpOp::Eq, libc::AF_UNIX as u64)?,
                condition(
                    1,
                    SeccompCmpOp::MaskedEq(
                        (!(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) as u32) as u64,
                    ),
                    libc::SOCK_STREAM as u64,
                )?,
                condition(2, SeccompCmpOp::Eq, 0)?,
            ])?],
        );
        // All new filesystem handles must be read-only; Landlock restricts paths.
        let forbidden =
            (libc::O_ACCMODE | libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND | libc::O_TMPFILE)
                as u64;
        rules.insert(
            libc::SYS_openat,
            vec![rule(vec![condition(
                2,
                SeccompCmpOp::MaskedEq(forbidden),
                0,
            )?])?],
        );
        #[cfg(target_arch = "x86_64")]
        rules.insert(
            libc::SYS_open,
            vec![rule(vec![condition(
                1,
                SeccompCmpOp::MaskedEq(forbidden),
                0,
            )?])?],
        );
        // Tokio and libc need only these benign socket/terminal queries.
        rules.insert(
            libc::SYS_ioctl,
            [libc::FIONBIO, libc::FIONREAD, libc::TCGETS]
                .into_iter()
                .map(|command| rule(vec![condition(1, SeccompCmpOp::Eq, command)?]))
                .collect::<Result<_>>()?,
        );
        rules.insert(
            libc::SYS_prctl,
            vec![rule(vec![condition(
                0,
                SeccompCmpOp::Eq,
                libc::PR_SET_NAME as u64,
            )?])?],
        );
        rules.insert(
            libc::SYS_tgkill,
            vec![rule(vec![condition(
                0,
                SeccompCmpOp::Eq,
                std::process::id() as u64,
            )?])?],
        );
        // No exec, fork/vfork, ptrace, process_vm_*, mount, namespaces, io_uring,
        // BPF, keyrings, arbitrary ioctl, file mutation, or new seccomp policies.
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            arch,
        )?
        .try_into()?;
        Ok(vec![clone3, filter])
    }
}

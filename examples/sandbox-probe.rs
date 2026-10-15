//! Run in a separate process; confinement is irreversible and inherited by threads.
#[path = "../src/sandbox.rs"]
mod sandbox;

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use std::{fs::File, os::fd::IntoRawFd, path::PathBuf};
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 3,
        "Usage: sandbox-probe SECRET_FILE FORBIDDEN_WRITE_PATH"
    );
    let secret = PathBuf::from(&args[1]);
    let write = PathBuf::from(&args[2]);
    let inherited = File::open(&secret)?.into_raw_fd();
    sandbox::install()?;
    // SAFETY: querying a deliberately inherited fd with no mutable pointers.
    ensure!(
        unsafe { libc::fcntl(inherited, libc::F_GETFD) } == -1,
        "Inherited descriptor survived confinement"
    );
    ensure!(std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF));
    check(&secret, &write)?;
    let worker_secret = secret.clone();
    let worker_write = write.clone();
    std::thread::spawn(move || check(&worker_secret, &worker_write))
        .join()
        .map_err(|_| anyhow::anyhow!("Thread probe panicked"))??;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let mut jobs = Vec::new();
        for _ in 0..8 {
            let secret = secret.clone();
            let write = write.clone();
            jobs.push(tokio::spawn(async move { check(&secret, &write) }));
        }
        for job in jobs {
            job.await.context("Tokio sandbox probe")??;
        }
        anyhow::Ok(())
    })?;
    println!(
        "PASS: Landlock/seccomp block file reads/writes, directory access, exec/fork, Unix/raw sockets, and executable mappings in main and worker threads"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn check(secret: &std::path::Path, write: &std::path::Path) -> anyhow::Result<()> {
    use anyhow::ensure;
    use std::{ffi::CString, fs, io, ptr};
    ensure!(
        fs::read("/etc/hosts").is_ok(),
        "Allowed DNS file cannot be read"
    );
    ensure!(
        fs::read(secret).unwrap_err().kind() == io::ErrorKind::PermissionDenied,
        "Secret file is readable"
    );
    ensure!(
        fs::write(write, b"forbidden").unwrap_err().kind() == io::ErrorKind::PermissionDenied,
        "File creation permitted"
    );
    ensure!(
        fs::read_dir(secret.parent().unwrap()).is_err(),
        "Directory enumeration permitted"
    );
    ensure!(
        std::net::TcpListener::bind("127.0.0.1:0").is_ok(),
        "Allowed TCP networking broken"
    );
    // SAFETY: these probes use valid syscall arguments. If fork were accidentally
    // allowed, the harmless child exits immediately. Failed mappings are not used.
    unsafe {
        let forked = libc::fork();
        if forked == 0 {
            libc::_exit(99);
        }
        ensure!(
            forked == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
            "fork permitted"
        );
        for (domain, kind) in [
            (libc::AF_UNIX, libc::SOCK_STREAM),
            (libc::AF_INET, libc::SOCK_RAW),
        ] {
            ensure!(
                libc::socket(domain, kind, 0) == -1
                    && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
                "Forbidden socket permitted"
            );
        }
        let memory = libc::mmap(
            ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        ensure!(memory != libc::MAP_FAILED, "Writable mapping failed");
        let protected = libc::mprotect(memory, 4096, libc::PROT_READ | libc::PROT_EXEC);
        let errno = io::Error::last_os_error().raw_os_error();
        libc::munmap(memory, 4096);
        ensure!(
            protected == -1 && errno == Some(libc::EPERM),
            "Executable mapping permitted"
        );
        let program = CString::new("/bin/true")?;
        let argv = [program.as_ptr(), ptr::null()];
        let envp: [*const libc::c_char; 1] = [ptr::null()];
        ensure!(
            libc::execve(program.as_ptr(), argv.as_ptr(), envp.as_ptr()) == -1
                && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
            "exec permitted"
        );
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    sandbox::install()
}

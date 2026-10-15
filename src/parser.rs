//! Disposable parser processes, forked by single-threaded supervisors started
//! before the network process loads its TLS key or enters confinement.
use crate::render::{RenderError, html_to_gemtext};
use anyhow::{Context, Result, bail, ensure};
use std::{
    io::{self, Read, Write},
    os::fd::{AsRawFd, FromRawFd, RawFd},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::OwnedSemaphorePermit;
use url::Url;

const MAX_BYTES: usize = 64 * 1024 * 1024;
const MEMORY_BYTES: libc::rlim_t = 512 * 1024 * 1024;
const FAILED: u8 = 3;
const TIMED_OUT: u8 = 4;

#[derive(Debug)]
pub enum Error {
    Render(RenderError),
    Failed,
    TimedOut,
}

struct Worker {
    input: Option<ChildStdin>,
    output: ChildStdout,
    child: Child,
}
impl Drop for Worker {
    fn drop(&mut self) {
        // EOF makes the supervisor exit; it always reaps its current child first.
        self.input.take();
        let _ = self.child.wait();
    }
}

#[derive(Clone)]
pub struct Pool(Arc<Mutex<Vec<Worker>>>);
impl Pool {
    pub fn new(count: usize) -> Result<Self> {
        let executable = std::env::current_exe().context("Locate parser executable")?;
        let mut workers = Vec::with_capacity(count);
        for _ in 0..count {
            let mut child = Command::new(&executable)
                .arg("--parser-supervisor")
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .context("Start parser supervisor")?;
            let mut output = child.stdout.take().unwrap();
            // Fail startup if confinement failed in any supervisor.
            let mut ready = [0];
            if output.read_exact(&mut ready).is_err() || ready != *b"R" {
                let _ = child.kill();
                let _ = child.wait();
                bail!("Parser supervisor failed to initialize");
            }
            workers.push(Worker {
                input: child.stdin.take(),
                output,
                child,
            });
        }
        Ok(Self(Arc::new(Mutex::new(workers))))
    }

    pub fn descriptors(&self) -> Vec<RawFd> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .flat_map(|worker| {
                [
                    worker.input.as_ref().unwrap().as_raw_fd(),
                    worker.output.as_raw_fd(),
                ]
            })
            .collect()
    }

    pub async fn render(
        &self,
        html: String,
        url: Url,
        full_page: bool,
        max_output: usize,
        deadline: tokio::time::Instant,
        permit: OwnedSemaphorePermit,
    ) -> Result<String, Error> {
        let pool = self.clone();
        tokio::task::spawn_blocking(move || {
            // Even if the caller times out, this slot stays occupied until the
            // supervisor has killed/reaped the child and returned its response.
            let _permit = permit;
            let mut worker = pool.0.lock().unwrap().pop().ok_or(Error::Failed)?;
            let result = (|| {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return Err(Error::TimedOut);
                }
                let input = worker.input.as_mut().unwrap();
                let millis = remaining.as_millis().clamp(1, 300_000) as u64;
                input
                    .write_all(&millis.to_be_bytes())
                    .map_err(|_| Error::Failed)?;
                input
                    .write_all(&(max_output as u64).to_be_bytes())
                    .map_err(|_| Error::Failed)?;
                input
                    .write_all(&[u8::from(full_page)])
                    .map_err(|_| Error::Failed)?;
                input
                    .write_all(&(url.as_str().len() as u64).to_be_bytes())
                    .map_err(|_| Error::Failed)?;
                input
                    .write_all(&(html.len() as u64).to_be_bytes())
                    .map_err(|_| Error::Failed)?;
                input
                    .write_all(url.as_str().as_bytes())
                    .map_err(|_| Error::Failed)?;
                input
                    .write_all(html.as_bytes())
                    .map_err(|_| Error::Failed)?;
                let (status, body) =
                    read_response(&mut worker.output, max_output).map_err(|_| Error::Failed)?;
                match status {
                    0 => String::from_utf8(body).map_err(|_| Error::Failed),
                    1 => Err(Error::Render(RenderError::TooLarge)),
                    2 => Err(Error::Render(RenderError::TooComplex)),
                    TIMED_OUT => Err(Error::TimedOut),
                    _ => Err(Error::Failed),
                }
            })();
            pool.0.lock().unwrap().push(worker);
            result
        })
        .await
        .map_err(|_| Error::Failed)?
    }
}

fn number(reader: &mut impl Read) -> io::Result<u64> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}
fn read_response(reader: &mut impl Read, limit: usize) -> io::Result<(u8, Vec<u8>)> {
    let mut status = [0];
    reader.read_exact(&mut status)?;
    let length = number(reader)?;
    if length > limit as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Parser response too large",
        ));
    }
    let mut body = vec![0; length as usize];
    reader.read_exact(&mut body)?;
    Ok((status[0], body))
}
fn response(writer: &mut impl Write, status: u8, body: &[u8]) -> io::Result<()> {
    writer.write_all(&[status])?;
    writer.write_all(&(body.len() as u64).to_be_bytes())?;
    writer.write_all(body)?;
    writer.flush()
}

pub fn supervise() -> Result<()> {
    crate::sandbox::install_parser_supervisor()?;
    let (status, _) = run_child(
        "<p>ready</p>",
        &Url::parse("https://example.org/")?,
        false,
        1024,
        Instant::now() + Duration::from_secs(5),
    )?;
    ensure!(status == 0, "Parser worker sandbox self-check failed");
    let mut input = io::stdin();
    let mut output = io::stdout();
    output.write_all(b"R")?;
    output.flush()?;
    loop {
        // EOF between jobs is normal shutdown. Truncated jobs fail closed.
        let mut first = [0];
        if input.read(&mut first)? == 0 {
            return Ok(());
        }
        let mut rest = [0; 7];
        input.read_exact(&mut rest)?;
        let mut bytes = [0; 8];
        bytes[0] = first[0];
        bytes[1..].copy_from_slice(&rest);
        let millis = u64::from_be_bytes(bytes);
        let deadline = Instant::now() + Duration::from_millis(millis.min(300_000));
        let max_output = number(&mut input)?;
        let mut full_page = [0];
        input.read_exact(&mut full_page)?;
        let url_bytes = number(&mut input)?;
        let html_bytes = number(&mut input)?;
        ensure!(
            (1..=300_000).contains(&millis)
                && max_output <= MAX_BYTES as u64
                && url_bytes <= 8192
                && html_bytes <= MAX_BYTES as u64
                && full_page[0] <= 1,
            "Invalid parser job limits"
        );
        let mut url = vec![0; url_bytes as usize];
        input.read_exact(&mut url)?;
        let url = Url::parse(std::str::from_utf8(&url)?)?;
        let mut html = vec![0; html_bytes as usize];
        input.read_exact(&mut html)?;
        let html = String::from_utf8(html)?;
        let (status, body) = run_child(
            &html,
            &url,
            full_page[0] != 0,
            max_output as usize,
            deadline,
        )
        .unwrap_or((FAILED, Vec::new()));
        // Transient pipe/fork failures fail this job without losing the slot.
        response(&mut output, status, &body)?;
    }
}

struct ChildGuard(libc::pid_t);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        // SAFETY: this PID belongs to our unreaped child, so it cannot be reused.
        unsafe { libc::kill(self.0, libc::SIGKILL) };
        // Always reap, including on timeout, oversized output, or I/O failure.
        loop {
            // SAFETY: wait for our own child; the status pointer may be null.
            if unsafe { libc::waitpid(self.0, std::ptr::null_mut(), 0) } >= 0
                || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
            {
                break;
            }
        }
    }
}

fn run_child(
    html: &str,
    url: &Url,
    full_page: bool,
    max_output: usize,
    deadline: Instant,
) -> Result<(u8, Vec<u8>)> {
    let mut fds = [-1; 2];
    // SAFETY: provides a valid two-element output array.
    ensure!(
        unsafe { libc::pipe(fds.as_mut_ptr()) } == 0,
        "Create parser result pipe: {}",
        io::Error::last_os_error()
    );
    // SAFETY: pipe succeeded and these descriptors are exclusively owned here.
    let mut reader = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    // SAFETY: same as above, for the other end of the pipe.
    let writer = unsafe { std::fs::File::from_raw_fd(fds[1]) };
    // SAFETY: supervisor is single-threaded, with no Tokio runtime. The child
    // only uses inherited memory/descriptors and exits without unwinding back.
    let pid = unsafe { libc::fork() };
    ensure!(
        pid >= 0,
        "Fork parser worker: {}",
        io::Error::last_os_error()
    );
    if pid == 0 {
        let result = (|| -> Result<()> {
            // SAFETY: duplicate a valid pipe descriptor onto stdout, and close
            // stdin so the parser cannot consume future supervisor jobs.
            ensure!(
                unsafe { libc::dup2(writer.as_raw_fd(), 1) } == 1,
                "Redirect parser output"
            );
            unsafe { libc::close(0) };
            set_limits(deadline)?;
            crate::sandbox::install_parser_worker()?;
            let (status, body) = match html_to_gemtext(html, url, full_page, max_output) {
                Ok(body) => (0, body.into_bytes()),
                Err(RenderError::TooLarge) => (1, Vec::new()),
                Err(RenderError::TooComplex) => (2, Vec::new()),
            };
            response(&mut io::stdout(), status, &body)?;
            Ok(())
        })();
        // SAFETY: exit only this disposable child; don't run inherited destructors.
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 1 }) };
    }
    let _child = ChildGuard(pid);
    drop(writer);
    let mut packet = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok((TIMED_OUT, Vec::new()));
        }
        let mut poll = libc::pollfd {
            fd: reader.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll points to one initialized descriptor; timeout is bounded.
        let result = unsafe {
            libc::poll(
                &mut poll,
                1,
                remaining.as_millis().clamp(1, i32::MAX as u128) as i32,
            )
        };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error()).context("Poll parser worker");
        }
        if result == 0 {
            continue;
        }
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        if packet.len() + n > max_output + 9 {
            return Ok((FAILED, Vec::new()));
        }
        packet.extend_from_slice(&chunk[..n]);
    }
    Ok(read_response(&mut packet.as_slice(), max_output).unwrap_or((FAILED, Vec::new())))
}

fn set_limits(deadline: Instant) -> Result<()> {
    let seconds = deadline.saturating_duration_since(Instant::now()).as_secs() + 1;
    let cpu = libc::rlimit {
        rlim_cur: seconds as libc::rlim_t,
        rlim_max: seconds as libc::rlim_t,
    };
    let memory = libc::rlimit {
        rlim_cur: MEMORY_BYTES,
        rlim_max: MEMORY_BYTES,
    };
    let core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    #[cfg(target_os = "linux")]
    let resource = libc::RLIMIT_AS;
    #[cfg(not(target_os = "linux"))]
    let resource = libc::RLIMIT_DATA;
    // SAFETY: all pointers reference initialized limits; only this child's
    // resource limits are changed, before it handles untrusted HTML.
    ensure!(
        unsafe { libc::setrlimit(libc::RLIMIT_CPU, &cpu) } == 0
            && unsafe { libc::setrlimit(resource, &memory) } == 0
            && unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core) } == 0,
        "Limit parser resources: {}",
        io::Error::last_os_error()
    );
    Ok(())
}

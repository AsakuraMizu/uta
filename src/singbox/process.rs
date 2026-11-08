//! The sing-box child process.

use std::{
    cell::RefCell,
    collections::VecDeque,
    future::Future,
    io::{self, Write},
    path::Path,
    process::Stdio,
    rc::Rc,
    time::{Duration, Instant},
};

use compio::{
    bytes::Bytes,
    io::framed::{Framed, codec::bytes::BytesCodec, frame::CharDelimited},
    process::{ChildStderr, Command},
    runtime::spawn,
};
use futures_channel::oneshot;
use futures_util::{
    FutureExt, StreamExt,
    future::{LocalBoxFuture, Shared},
};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};

use super::READY;

/// Lines of sing-box output kept for error reports.
const TAIL_LINES: usize = 40;

pub struct Process {
    pid: Pid,
    started: Instant,
    exit: Shared<LocalBoxFuture<'static, String>>,
    log: Rc<RefCell<Log>>,
}

#[derive(Default)]
struct Log {
    tail: VecDeque<String>,
    /// How many startup lines sing-box has logged; every reload logs another.
    ready: u64,
    waiters: Vec<oneshot::Sender<()>>,
}

impl Process {
    /// Starts `sing-box run` on a configuration directory, with `work_dir` as
    /// its working directory, and forwards its log to the standard error of
    /// uta.
    pub fn spawn(binary: &Path, config_dir: &Path, work_dir: &Path) -> io::Result<Self> {
        let mut command = Command::new(binary);
        command
            .arg("run")
            .arg("--disable-color")
            .arg("-C")
            .arg(config_dir)
            .arg("-D")
            .arg(work_dir)
            // A terminal's Ctrl+C reaches uta, which stops sing-box after removing its rules.
            .process_group(0);
        // Converting a `Stdio` cannot fail.
        let Ok(command) = command.stdin(Stdio::null());
        let Ok(command) = command.stdout(Stdio::null());
        let Ok(command) = command.stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let pid = Pid::from_raw(child.id().try_into().expect("pid fits in i32"));
        let stderr = child.stderr.take().expect("stderr is piped");

        let log = Rc::new(RefCell::new(Log::default()));
        spawn(read_log(stderr, Rc::clone(&log))).detach();

        let exit = async move {
            match child.wait().await {
                Ok(status) => status.to_string(),
                Err(error) => format!("failed to wait for sing-box: {error}"),
            }
        }
        .boxed_local()
        .shared();
        // Reap the child even when no one is waiting for it.
        spawn(exit.clone()).detach();

        Ok(Self {
            pid,
            started: Instant::now(),
            exit,
            log,
        })
    }

    pub fn pid(&self) -> u32 {
        self.pid.as_raw().cast_unsigned()
    }

    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }

    /// Resolves with the exit status once sing-box has exited.
    pub fn exited(&self) -> impl Future<Output = String> + use<> {
        self.exit.clone()
    }

    pub fn has_exited(&self) -> bool {
        self.exit.peek().is_some()
    }

    /// How many times sing-box has reported startup so far.
    pub fn ready_count(&self) -> u64 {
        self.log.borrow().ready
    }

    /// Resolves once sing-box has reported startup more than `count` times.
    pub async fn ready_after(&self, count: u64) {
        loop {
            let receiver = {
                let mut log = self.log.borrow_mut();
                if log.ready > count {
                    return;
                }
                let (sender, receiver) = oneshot::channel();
                log.waiters.push(sender);
                receiver
            };
            // A dropped sender means the log reached its end; the exit future
            // reports that.
            if receiver.await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }

    pub fn signal(&self, signal: Signal) -> io::Result<()> {
        // After exit the child is reaped and its PID may belong to another
        // process.
        if self.has_exited() {
            return Ok(());
        }
        kill(self.pid, signal).map_err(io::Error::from)
    }

    /// The last lines sing-box logged.
    pub fn tail(&self) -> String {
        let log = self.log.borrow();
        let lines: Vec<&str> = log.tail.iter().map(String::as_str).collect();
        lines.join("\n")
    }
}

async fn read_log(stderr: ChildStderr, log: Rc<RefCell<Log>>) {
    let mut lines = Framed::new::<Bytes, Bytes>(BytesCodec::new(), CharDelimited::<'\n'>::new())
        .with_reader(stderr);
    while let Some(Ok(line)) = lines.next().await {
        let line = String::from_utf8_lossy(&line).into_owned();
        // A failed write to uta's own stderr must not stop the readiness
        // tracking.
        let _ = writeln!(io::stderr(), "{line}");
        let mut log = log.borrow_mut();
        if line.contains(READY) {
            log.ready += 1;
            for waiter in log.waiters.drain(..) {
                let _ = waiter.send(());
            }
        }
        if log.tail.len() == TAIL_LINES {
            log.tail.pop_front();
        }
        log.tail.push_back(line);
    }
    log.borrow_mut().waiters.clear();
}

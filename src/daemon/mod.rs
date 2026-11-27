//! The daemon: runs sing-box, owns the kernel state, and serves the control
//! socket.

mod apply;
mod cgroup;

use std::{
    cell::{Cell, RefCell},
    fs, io,
    os::{
        linux::net::SocketAddrExt,
        unix::{
            ffi::OsStrExt,
            fs::PermissionsExt,
            net::{SocketAddr, UnixDatagram, UnixListener as StdListener, UnixStream as StdStream},
        },
    },
    path::{Path, PathBuf},
    rc::Rc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use caps::{CapSet, Capability};
use compio::{
    net::{UnixListener, UnixStream},
    runtime::spawn,
    signal::unix::signal,
    time::{sleep, timeout},
};
use futures_channel::{mpsc::UnboundedReceiver, oneshot};
use futures_util::{FutureExt, SinkExt, StreamExt, lock::Mutex, pin_mut, select};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_sys::SocketAddr as NetlinkAddr;
use nix::sys::{
    signal::Signal,
    socket::{getsockopt, sockopt::PeerCredentials},
};
use rtnetlink::packet_core::NetlinkMessage;

use crate::{
    config::{
        Config, SingBox,
        rules::{self, Rule},
    },
    kernel::{self, Kernel, netlink},
    rpc::{self, Executable, Request, Response, RuleStatus, RunStatus, Status},
    selection::{
        CGROUP_ROOT, Cgroup, Match, Selection,
        resolve::{self, Resolved},
        watch::Watcher,
    },
    singbox::{self, Files, Level, Process},
};

/// How long sing-box may take to report startup, which includes fetching remote
/// rule-sets.
const READY_TIMEOUT: Duration = Duration::from_secs(60);
/// How long sing-box may take to exit after SIGTERM before it is killed.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
/// Kernel objects are per network namespace, and so is the abstract socket
/// namespace.
const INSTANCE_NAME: &[u8] = b"uta";

pub struct Options {
    pub config: PathBuf,
    pub rules: PathBuf,
    pub runtime_dir: PathBuf,
}

type Connection = rpc::Connection<Response, Request>;

struct Daemon {
    config: Config,
    rules_path: PathBuf,
    paths: Paths,
    executable: Executable,
    kernel: Mutex<Kernel>,
    watcher: Watcher,
    state: RefCell<State>,
    stopping: Cell<bool>,
    fatal: RefCell<Option<oneshot::Sender<String>>>,
}

struct Paths {
    socket: PathBuf,
    /// The configuration sing-box runs.
    current: PathBuf,
    /// A configuration being checked before it replaces the current one.
    staging: PathBuf,
    /// The configuration the current one replaced, kept until the change is
    /// final.
    previous: PathBuf,
    merged: PathBuf,
}

impl Paths {
    fn new(dir: &Path) -> Self {
        Self {
            socket: dir.join("uta.sock"),
            current: dir.join("sing-box"),
            staging: dir.join("sing-box.new"),
            previous: dir.join("sing-box.old"),
            merged: dir.join("merged.json"),
        }
    }
}

struct State {
    process: Rc<Process>,
    /// The log filter of the configuration sing-box runs, and of the one a
    /// reload replaced.
    log_filter: Option<Level>,
    previous_log_filter: Option<Level>,
    /// An operation is replacing or reloading sing-box and handles its exit
    /// itself.
    replacing: bool,
    applied: Applied,
    /// Rules installed while waiting for confirmation.
    trial: Option<Applied>,
    /// The scopes of `uta run`.
    runs: Vec<Run>,
    operation: Option<Operation>,
    /// The change waiting for confirmation.
    pending: Option<Pending>,
}

/// A change waiting for confirmation, which any client may decide.
struct Pending {
    /// The rules the client asked for, which a confirming client writes to the
    /// rules file.
    rules: Option<String>,
    decide: oneshot::Sender<Decision>,
}

/// Whether to keep the change waiting for confirmation, and where to report
/// the outcome.
struct Decision {
    keep: bool,
    reply: oneshot::Sender<Response>,
}

/// A `uta run` scope and the sources captured along with it.
struct Run {
    cgroup: Cgroup,
    with: Vec<Rule>,
    resolved: Resolved,
}

/// The rules in effect.
#[derive(Clone)]
struct Applied {
    text: String,
    rules: Vec<Rule>,
    resolved: Resolved,
}

impl Applied {
    fn selection(&self) -> Selection {
        let mut selection = Selection::default();
        self.resolved.add_to(&self.rules, &mut selection);
        selection.normalize();
        selection
    }
}

struct Operation {
    kind: &'static str,
    deadline: Option<Instant>,
}

pub async fn run(options: Options) -> Result<()> {
    inherit_capabilities()?;
    // Leftovers of a daemon that died are removed even when the configuration
    // it ran no longer loads.
    let _instance = acquire_instance()?;
    let mut kernel = Kernel::new(netlink::connect()?);
    kernel
        .remove()
        .await
        .context("failed to remove leftover kernel state")?;

    let config = Config::load(&options.config)?;
    let text = read_rules(&options.rules)?;
    let rules =
        rules::parse(&text).with_context(|| format!("invalid {}", options.rules.display()))?;
    let resolved = resolve::resolve(&rules, Path::new(CGROUP_ROOT))?;
    let routing = netlink::watch_routing().context("failed to watch policy routing")?;
    let nftables = netlink::NftablesEvents::new().context("failed to watch nftables")?;
    let watcher = Watcher::new().context("failed to watch the cgroup tree")?;
    watcher.set_dirs(&resolved.dirs);
    let paths = Paths::new(&std::path::absolute(&options.runtime_dir)?);

    Files::collect(&config)?.write(&paths.current)?;
    let log_filter = check(&config, &paths.current, &paths.merged).await?;
    let process = Rc::new(Process::spawn(
        &config.singbox.binary,
        &paths.current,
        &config.singbox.work_dir,
    )?);
    process.filter_log(log_filter);
    let started = async {
        wait_ready(&process, 0).await?;
        let mut selection = Selection::default();
        resolved.add_to(&rules, &mut selection);
        selection.normalize();
        kernel.install(&selection, &config).await?;
        let listener = bind(&paths.socket)?;
        notify_ready()?;
        Ok(listener)
    }
    .await;
    let listener = match started {
        Ok(listener) => listener,
        Err(error) => {
            let _ = kernel.remove().await;
            stop(&process).await;
            return Err(error);
        }
    };
    eprintln!("capturing traffic for {} rules", rules.len());

    let (fatal, fatal_receiver) = oneshot::channel();
    let daemon = Rc::new(Daemon {
        config,
        rules_path: options.rules,
        paths,
        executable: Executable::current()?,
        kernel: Mutex::new(kernel),
        watcher,
        state: RefCell::new(State {
            process: Rc::clone(&process),
            log_filter,
            previous_log_filter: None,
            replacing: false,
            applied: Applied {
                text,
                rules,
                resolved,
            },
            trial: None,
            runs: Vec::new(),
            operation: None,
            pending: None,
        }),
        stopping: Cell::new(false),
        fatal: RefCell::new(Some(fatal)),
    });
    daemon.watch(&process);
    spawn(Rc::clone(&daemon).track()).detach();
    spawn(Rc::clone(&daemon).keep_routes(routing)).detach();
    spawn(Rc::clone(&daemon).keep_table(nftables)).detach();
    let served = daemon.serve(listener, fatal_receiver).await;
    let stopped = daemon.shutdown().await;
    served.and(stopped)
}

impl Daemon {
    async fn serve(
        self: &Rc<Self>,
        listener: UnixListener,
        fatal: oneshot::Receiver<String>,
    ) -> Result<()> {
        let terminate = signal(Signal::SIGTERM as i32).fuse();
        let interrupt = signal(Signal::SIGINT as i32).fuse();
        let fatal = fatal.fuse();
        pin_mut!(terminate, interrupt, fatal);
        let mut incoming = listener.incoming().fuse();
        loop {
            select! {
                stream = incoming.next() => match stream {
                    Some(Ok(stream)) => {
                        spawn(Rc::clone(self).handle(stream)).detach();
                    }
                    Some(Err(error)) => eprintln!("failed to accept a connection: {error}"),
                    None => bail!("the control socket closed"),
                },
                result = terminate => return result.context("failed to wait for SIGTERM"),
                result = interrupt => return result.context("failed to wait for SIGINT"),
                reason = fatal => return Err(anyhow!(reason.unwrap_or_default())),
            }
        }
    }

    /// Removes the kernel state and stops sing-box.
    async fn shutdown(&self) -> Result<()> {
        self.stopping.set(true);
        let removed = self.kernel.lock().await.remove().await;
        stop(&self.process()).await;
        let _ = fs::remove_file(&self.paths.socket);
        removed
    }

    fn process(&self) -> Rc<Process> {
        Rc::clone(&self.state.borrow().process)
    }

    /// Fails open when `process` exits on its own: the kernel stops capturing
    /// and the daemon exits, for systemd to restart it.
    fn watch(self: &Rc<Self>, process: &Rc<Process>) {
        let daemon = Rc::clone(self);
        let process = Rc::clone(process);
        spawn(async move {
            let status = process.exited().await;
            let expected = {
                let state = daemon.state.borrow();
                daemon.stopping.get() || state.replacing || !Rc::ptr_eq(&state.process, &process)
            };
            if expected {
                return;
            }
            let mut reason = format!("sing-box exited ({status})");
            if let Err(error) = daemon.kernel.lock().await.remove().await {
                reason = format!("{reason}, and removing the kernel state failed: {error:#}");
            }
            daemon.fail(reason);
        })
        .detach();
    }

    fn fail(&self, reason: String) {
        if let Some(fatal) = self.fatal.borrow_mut().take() {
            let _ = fatal.send(reason);
        }
    }

    async fn handle(self: Rc<Self>, stream: UnixStream) {
        let peer = getsockopt(&stream, PeerCredentials).map(|credentials| credentials.pid());
        let mut connection = rpc::framed(stream);
        if let Err(error) = self.converse(&mut connection, peer).await {
            let _ = connection.send(Response::Error(format!("{error:#}"))).await;
        }
    }

    async fn converse(
        self: &Rc<Self>,
        connection: &mut Connection,
        peer: nix::Result<i32>,
    ) -> Result<()> {
        match connection.next().await {
            Some(Ok(Request::Hello(executable))) if executable == self.executable => {
                connection
                    .send(Response::Hello {
                        rules: self.rules_path.clone(),
                    })
                    .await?;
            }
            Some(Ok(Request::Hello(_))) => {
                bail!("the daemon runs a different uta executable; restart the daemon")
            }
            None => return Ok(()),
            _ => bail!("expected a hello"),
        }
        match connection.next().await {
            Some(Ok(Request::Status)) => {
                let status = self.status().await;
                connection.send(Response::Status(status)).await?;
            }
            Some(Ok(Request::Apply {
                rules,
                confirm_secs,
                pending,
            })) => self.apply(connection, rules, confirm_secs, pending).await?,
            Some(Ok(Request::Confirm)) => self.confirm(connection).await?,
            Some(Ok(Request::Rollback)) => self.decide(connection, false).await?,
            Some(Ok(Request::Covered)) => {
                let pid = peer.context("failed to identify the client")?;
                let covered = self.covers(pid)?;
                connection.send(Response::Covered(covered)).await?;
            }
            Some(Ok(Request::Run { with })) => {
                let pid = peer.context("failed to identify the client")?;
                let with = with
                    .iter()
                    .map(|rule| Rule::parse_include(rule))
                    .collect::<Result<_, _>>()?;
                self.add_run(pid, with).await?;
                connection.send(Response::Captured).await?;
            }
            None => {}
            _ => bail!("unexpected request"),
        }
        Ok(())
    }

    /// Puts back the policy routing whenever another program removes it, as
    /// systemd-networkd does to rules it did not configure when it starts.
    async fn keep_routes(
        self: Rc<Self>,
        mut messages: UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, NetlinkAddr)>,
    ) {
        while let Some((message, _)) = messages.next().await {
            // Handle a burst of deletions at once.
            let mut removed = kernel::removes_ours(&message);
            while let Ok((message, _)) = messages.try_recv() {
                removed |= kernel::removes_ours(&message);
            }
            if !removed {
                continue;
            }
            match self.kernel.lock().await.restore_routes(&self.config).await {
                Ok(0) => {}
                Ok(restored) => {
                    eprintln!(
                        "put back policy routing another program removed ({restored} entries)"
                    );
                }
                Err(error) => eprintln!("{error:#}"),
            }
        }
    }

    /// Puts back the nftables table whenever another program deletes it, as
    /// `nft flush ruleset` does.
    async fn keep_table(self: Rc<Self>, events: netlink::NftablesEvents) {
        loop {
            if let Err(error) = events.table_deleted().await {
                eprintln!("stopped watching nftables: {error}");
                return;
            }
            if !self.kernel.lock().await.forget_deleted_table().await {
                continue;
            }
            match self.sync().await {
                Ok(()) => eprintln!("put back the nftables table another program removed"),
                Err(error) => eprintln!("failed to put back the nftables table: {error:#}"),
            }
        }
    }

    async fn status(&self) -> Status {
        let missing = match self.kernel.lock().await.missing(&self.config).await {
            Ok(missing) => missing,
            Err(error) => vec![format!("unknown, {error:#}")],
        };
        let state = self.state.borrow();
        let applied = &state.applied;
        let rules = applied
            .rules
            .iter()
            .zip(&applied.resolved.notes)
            .map(|(rule, note)| RuleStatus {
                rule: rule.to_string(),
                resolved: note.clone(),
            })
            .collect();
        let rules_changed = read_rules(&self.rules_path).map_or(true, |text| text != applied.text);
        let singbox_changed = Files::collect(&self.config)
            .and_then(|files| Ok(!files.matches(&self.paths.current)?))
            .unwrap_or(true);
        Status {
            singbox_pid: state.process.pid(),
            singbox_uptime_secs: state.process.uptime().as_secs(),
            rules_path: self.rules_path.clone(),
            rules,
            runs: state
                .runs
                .iter()
                .map(|run| RunStatus {
                    cgroup: format!("/{}", run.cgroup.path),
                    with: run.with.iter().map(ToString::to_string).collect(),
                })
                .collect(),
            operation: state.operation.as_ref().map(Operation::describe),
            rules_changed,
            singbox_changed,
            missing,
        }
    }

    /// Makes the kernel capture what the rules in effect and the `uta run`
    /// scopes select.
    async fn sync(&self) -> Result<()> {
        let mut kernel = self.kernel.lock().await;
        loop {
            // Shutdown removes the kernel state; a task that outlives it must
            // not install it again.
            if self.stopping.get() {
                bail!("the daemon is stopping");
            }
            if self.process().has_exited() {
                bail!("sing-box is not running");
            }
            let selection = self.selection();
            let Err(error) = kernel.install(&selection, &self.config).await else {
                return Ok(());
            };
            // nft fails on a cgroup removed since the tree was read; read it
            // again.
            self.refresh();
            let root = Path::new(CGROUP_ROOT);
            let ended: Vec<String> = self
                .state
                .borrow()
                .runs
                .iter()
                .filter(|run| {
                    Cgroup::at(root, run.cgroup.path.clone()).ok().as_ref() != Some(&run.cgroup)
                })
                .map(|run| run.cgroup.path.clone())
                .collect();
            for run in &ended {
                eprintln!("/{run} has no process left");
                self.end_run(run);
            }
            if self.selection() == selection {
                return Err(error);
            }
        }
    }

    fn selection(&self) -> Selection {
        let state = self.state.borrow();
        let rules = state.trial.as_ref().unwrap_or(&state.applied);
        let mut selection = Selection::default();
        rules.resolved.add_to(&rules.rules, &mut selection);
        for run in &state.runs {
            selection.include.push(Match::cgroup(&run.cgroup));
            run.resolved.add_to(&run.with, &mut selection);
        }
        selection.normalize();
        selection
    }

    fn update_watches(&self) {
        let state = self.state.borrow();
        let mut dirs = state.applied.resolved.dirs.clone();
        if let Some(trial) = &state.trial {
            dirs.extend(trial.resolved.dirs.iter().cloned());
        }
        for run in &state.runs {
            dirs.extend(run.resolved.dirs.iter().cloned());
        }
        self.watcher.set_dirs(&dirs);
    }
}

fn read_rules(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}

/// Checks the configuration in `dir` and returns the level below which its
/// log lines are dropped; see [`singbox::log_filter`].
async fn check(config: &Config, dir: &Path, merged: &Path) -> Result<Option<Level>> {
    let SingBox {
        binary, work_dir, ..
    } = &config.singbox;
    singbox::check(binary, work_dir, dir).await?;
    let filter = singbox::log_filter(&singbox::merge(binary, work_dir, dir, merged).await?);
    if filter.is_some() {
        singbox::log_at_info(dir)?;
    }
    Ok(filter)
}

async fn wait_ready(process: &Process, count: u64) -> Result<()> {
    let ready = process.ready_after(count).fuse();
    let exited = process.exited().fuse();
    let expired = sleep(READY_TIMEOUT).fuse();
    pin_mut!(ready, exited, expired);
    select! {
        () = ready => Ok(()),
        status = exited => bail!("sing-box exited ({status}):\n{}", process.tail()),
        () = expired => bail!(
            "sing-box did not report startup within {}s:\n{}",
            READY_TIMEOUT.as_secs(),
            process.tail()
        ),
    }
}

async fn stop(process: &Process) {
    let _ = process.signal(Signal::SIGTERM);
    if timeout(STOP_TIMEOUT, process.exited()).await.is_err() {
        let _ = process.signal(Signal::SIGKILL);
        process.exited().await;
    }
}

/// The capabilities uta works with, which the programs it runs, sing-box and
/// nft, need too.
const CAPABILITIES: [Capability; 2] = [Capability::CAP_NET_ADMIN, Capability::CAP_NET_BIND_SERVICE];

/// Makes the capabilities uta holds effective, and ambient so the programs it
/// runs keep them. Started with them ambient, as by systemd or setpriv, this
/// changes nothing; started from a file that has them permitted (setcap(8)),
/// this is what passes them on. Only the daemon and `uta cleanup` do this, so
/// what `uta run` runs never gains them.
pub fn inherit_capabilities() -> Result<()> {
    let permitted = caps::read(None, CapSet::Permitted).context("failed to read capabilities")?;
    for capability in CAPABILITIES.into_iter().filter(|c| permitted.contains(c)) {
        for set in [CapSet::Effective, CapSet::Inheritable, CapSet::Ambient] {
            caps::raise(None, set, capability)
                .with_context(|| format!("failed to raise {capability}"))?;
        }
    }
    Ok(())
}

/// Claims the network namespace for one daemon, or for `uta cleanup`, until the
/// returned listener is dropped.
pub fn acquire_instance() -> Result<StdListener> {
    use std::os::linux::net::SocketAddrExt;

    let address = SocketAddr::from_abstract_name(INSTANCE_NAME)?;
    match StdListener::bind_addr(&address) {
        Ok(listener) => Ok(listener),
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
            match StdStream::connect_addr(&address)
                .map(|stream| getsockopt(&stream, PeerCredentials))
            {
                Ok(Ok(owner)) => bail!(
                    "a uta daemon is running (pid {}, uid {})",
                    owner.pid(),
                    owner.uid()
                ),
                _ => bail!("a uta daemon is running"),
            }
        }
        Err(error) => Err(error).context("failed to claim the network namespace"),
    }
}

fn bind(path: &Path) -> Result<UnixListener> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            return Err(error).with_context(|| format!("failed to remove {}", path.display()));
        }
        _ => {}
    }
    let listener = StdListener::bind(path)
        .with_context(|| format!("failed to listen on {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    Ok(UnixListener::from_std(listener)?)
}

/// Tells systemd that the daemon is ready, if it runs the daemon as a
/// `Type=notify` service (sd_notify(3)).
fn notify_ready() -> Result<()> {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let address = match path.as_bytes().strip_prefix(b"@") {
        Some(name) => SocketAddr::from_abstract_name(name)?,
        None => SocketAddr::from_pathname(&path)?,
    };
    UnixDatagram::unbound()?
        .send_to_addr(b"READY=1", &address)
        .with_context(|| format!("failed to notify systemd at {}", path.display()))?;
    Ok(())
}

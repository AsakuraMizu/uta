//! Command-line interface. Every command except `daemon` and `cleanup` talks
//! to the daemon over its control socket.

mod apply;
mod run;
mod status;

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use compio::net::UnixStream;
use futures_util::{SinkExt, StreamExt};

use self::apply::Change;
use crate::{
    config::rules::Rule,
    daemon,
    kernel::{Kernel, netlink},
    rpc::{self, Executable, Request, Response},
};

type Connection = rpc::Connection<Request, Response>;

const RULES_HELP: &str = "\
Rules:
A rule is conditions separated by spaces, all of which must hold; quote it in the shell. A rule
starting with ! excludes what it matches. Traffic is captured when it matches a rule that does
not exclude, and no rule that does. A rule that does not exclude needs a source.

Sources, sockets of this host:
  local          every socket
  uid:USERS      sockets of users, by name, ID or ID range
  gid:GROUPS     sockets created with a group as the effective group
  cgroup:/PATHS  processes in cgroups or below them; * matches within one path segment
Sources, forwarded traffic:
  iif:NAMES      entering through an interface; a trailing * matches a prefix
  src:ADDRS      from addresses or networks
  mac:ADDRS      from link-layer addresses
Other conditions:
  proto:tcp|udp
  dst:ADDRS      to addresses or networks
  port:PORTS     to ports or port ranges
  oif:NAMES      that routing sends out of an interface

Values separated by commas are alternatives, and kind:!VALUES negates a condition. For example,
`!dst:10.0.0.0/8 port:!53` leaves traffic to 10.0.0.0/8 alone, except DNS. The rules file holds
one rule per line; # starts a comment.";

#[derive(Parser)]
#[command(version, about = "Transparent proxy controller for sing-box")]
struct Cli {
    /// The daemon's control socket [default: $XDG_RUNTIME_DIR/uta/uta.sock if
    /// it exists, else /run/uta/uta.sock]
    #[arg(long, env = "UTA_SOCKET")]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show what the daemon runs and captures
    Status,
    /// Add rules to the rules file and apply them
    #[command(after_help = RULES_HELP)]
    Add {
        #[arg(required = true, value_name = "RULE")]
        rules: Vec<Rule>,
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Remove rules from the rules file and apply the result
    #[command(after_help = RULES_HELP)]
    Del {
        #[arg(required = true, value_name = "RULE")]
        rules: Vec<Rule>,
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Apply the rules file and the sing-box configuration
    #[command(after_help = RULES_HELP)]
    Apply {
        #[command(flatten)]
        confirm: Confirm,
    },
    /// Run a command, or $SHELL, with its traffic captured
    Run {
        /// Also capture what RULE selects while the command runs; a rule that
        /// does not exclude
        #[arg(long, value_name = "RULE", value_parser = Rule::parse_include)]
        with: Vec<Rule>,
        /// Run inside the scope `uta run` created
        #[arg(long, hide = true)]
        in_scope: bool,
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        command: Vec<OsString>,
    },
    /// Run the daemon
    Daemon {
        /// uta.toml
        #[arg(long)]
        config: PathBuf,
        /// The rules file
        #[arg(long)]
        rules: PathBuf,
        /// Directory for the control socket and the sing-box configuration uta
        /// assembles
        #[arg(long, env = "RUNTIME_DIRECTORY")]
        runtime_dir: PathBuf,
    },
    /// Remove the kernel state of a daemon that did not exit cleanly
    Cleanup,
}

#[derive(Args)]
struct Confirm {
    /// Keep a change to the captured traffic without asking
    #[arg(long)]
    yes: bool,
    /// Seconds to wait for confirmation before rolling back
    #[arg(long, default_value_t = 90, value_name = "SECONDS")]
    timeout: u64,
}

pub fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match compio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("uta: failed to start the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("uta: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<bool> {
    let socket = || socket_path(cli.socket.clone());
    match cli.command {
        Command::Status => status::status(&socket()).await.map(|()| true),
        Command::Add { rules, confirm } => {
            apply::apply(&socket(), Change::Add(rules), confirm.yes, confirm.timeout).await
        }
        Command::Del { rules, confirm } => {
            apply::apply(&socket(), Change::Del(rules), confirm.yes, confirm.timeout).await
        }
        Command::Apply { confirm } => {
            apply::apply(&socket(), Change::File, confirm.yes, confirm.timeout).await
        }
        Command::Run {
            with,
            in_scope,
            command,
        } => run::run(&socket(), &with, in_scope, command).await,
        Command::Daemon {
            config,
            rules,
            runtime_dir,
        } => daemon::run(daemon::Options {
            config,
            rules,
            runtime_dir,
        })
        .await
        .map(|()| true),
        Command::Cleanup => {
            let _instance = daemon::acquire_instance()?;
            Kernel::new(netlink::connect()?).remove().await?;
            Ok(true)
        }
    }
}

/// The control socket: the one given, or the first that exists of the user's
/// runtime directory and the system's.
fn socket_path(given: Option<PathBuf>) -> PathBuf {
    if let Some(path) = given {
        return path;
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        let path = Path::new(&runtime).join("uta/uta.sock");
        if path.exists() {
            return path;
        }
    }
    PathBuf::from("/run/uta/uta.sock")
}

/// Connects to the daemon. Returns the connection and the daemon's rules file.
async fn connect(socket: &Path) -> Result<(Connection, PathBuf)> {
    let stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("failed to connect to the daemon at {}", socket.display()))?;
    let mut connection = rpc::framed(stream);
    connection
        .send(Request::Hello(Executable::current()?))
        .await?;
    match receive(&mut connection).await? {
        Response::Hello { rules } => Ok((connection, rules)),
        Response::Error(message) => bail!("{message}"),
        response => unexpected(response),
    }
}

async fn receive(connection: &mut Connection) -> Result<Response> {
    match connection.next().await {
        Some(response) => Ok(response?),
        None => bail!("the daemon closed the connection"),
    }
}

fn unexpected<T>(response: Response) -> Result<T> {
    bail!("unexpected response from the daemon: {response:?}")
}

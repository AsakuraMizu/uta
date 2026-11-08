//! Transparent proxy controller for sing-box.

mod cli;
mod config;
mod daemon;
mod kernel;
mod rpc;
mod selection;
mod singbox;

fn main() -> std::process::ExitCode {
    cli::main()
}

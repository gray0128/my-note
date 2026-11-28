pub mod cli;
pub mod clip_watch;
pub mod clipboard;
pub mod daemon;
pub mod formatters;
pub mod help;
pub mod local_ipc;
pub mod output;
pub mod runner;
pub mod sync_client;

pub fn run() -> i32 {
    runner::run_from(std::env::args_os())
}

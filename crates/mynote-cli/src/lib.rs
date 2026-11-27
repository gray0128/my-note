pub mod cli;
pub mod clip_watch;
pub mod clipboard;
pub mod daemon;
pub mod formatters;
pub mod help;
pub mod output;
pub mod runner;
pub mod sync_client;
pub mod uds;

pub fn run() -> i32 {
    runner::run_from(std::env::args_os())
}

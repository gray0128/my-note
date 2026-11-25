pub mod cli;
pub mod formatters;
pub mod help;
pub mod output;
pub mod runner;

pub fn run() -> i32 {
    runner::run_from(std::env::args_os())
}

//! `acp` — the binary. Argument parsing, one tokio runtime, and the exit code.
//!
//! Everything else is in [`cli`], which is a module of *this* crate rather than of the library:
//! the library is what the tests and the macOS app link, and neither wants the CLI's parser or its
//! `anyhow` chain. `anyhow` is confined to these two files (design, § `src/main.rs`, `src/cli.rs`).
//!
//! Nothing here writes to stdout. `acp serve` runs the MCP server on stdio, so stdout is a protocol
//! channel; a failure is reported on stderr and becomes an exit code.

mod cli;

use std::process::ExitCode;

use clap::Parser as _;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("acp: could not start the async runtime: {err}");
            return ExitCode::FAILURE;
        }
    };

    let result = runtime.block_on(cli::run(cli));

    // Dropping a runtime waits for every **blocking** task, and `serve`'s MCP transport parks one:
    // `tokio::io::stdin` reads on the blocking pool, and that read only ends when the peer closes
    // the pipe. Waiting for it would hang an exit the daemon has already finished — the log is
    // flushed and the lock and socket are unlinked before `run` returns — so the runtime is left to
    // its own devices instead.
    runtime.shutdown_background();

    match result {
        // The code is a *result* — `serve` answers 3 when another daemon holds the lock — so it is
        // passed through as it is, with anything unrepresentable collapsing to a plain failure.
        Ok(code) => u8::try_from(code).map_or(ExitCode::FAILURE, ExitCode::from),
        Err(err) => {
            eprintln!("acp: {err:#}");
            ExitCode::FAILURE
        }
    }
}

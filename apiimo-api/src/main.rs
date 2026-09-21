//! `apiimo` command-line binary: the Python tool's CLI, rebuilt on the Rust
//! workspace. Machine-readable output is available with `--json` (printed
//! after parsing, before the human rendering is skipped).

use std::process::ExitCode;

use apiimo_api::{parse, render, usage, Apiimo};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|arg| arg == "--json");
    let args: Vec<String> = args.into_iter().filter(|arg| arg != "--json").collect();

    let invocation = match parse(args) {
        Ok(invocation) => invocation,
        Err(error) => {
            eprintln!("apiimo: {error}");
            eprintln!();
            eprint!("{}", usage());
            return ExitCode::from(2);
        }
    };
    if invocation.help_only {
        print!("{}", usage());
        return ExitCode::SUCCESS;
    }

    let mut apiimo = match &invocation.game_dir {
        Some(game_dir) => Apiimo::with_game_dir(game_dir),
        None => Apiimo::discover(),
    };
    if let Some(output_dir) = &invocation.output_dir {
        apiimo.set_output_dir(output_dir);
    }
    if let Some(dumper_command) = &invocation.dumper_command {
        apiimo.set_dumper_command(dumper_command);
    }

    match apiimo.run(&invocation.command) {
        Ok(output) => {
            if json {
                println!("{}", output.to_json());
            } else {
                print!("{}", render(&output));
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("apiimo: {error}");
            ExitCode::FAILURE
        }
    }
}

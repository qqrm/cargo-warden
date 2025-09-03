use clap::{Parser, Subcommand};

/// Cargo subcommand providing warden functionality.
#[derive(Parser)]
#[command(name = "cargo-warden", version, about = "Cargo Warden CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build wrapper that will configure isolation.
    Build {
        /// Arguments passed to `cargo build`.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Run wrapper for arbitrary commands.
    Run {
        /// Command to execute after `--`.
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Build { args } => {
            println!("build not implemented: {:?}", args);
        }
        Commands::Run { cmd } => {
            println!("run not implemented: {:?}", cmd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }
}

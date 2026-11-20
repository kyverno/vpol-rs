mod api;
mod cel_kyverno;
mod provider;
mod server;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context as _;
use clap::{Parser, Subcommand};

use crate::provider::Provider;

/// Evaluates Kyverno validating policies against JSON objects.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve `POST /evaluate` over HTTP.
    Serve {
        /// Policy files or directories of them. Repeatable.
        #[arg(short, long = "policies", required = true)]
        policies: Vec<PathBuf>,

        /// Address to listen on.
        #[arg(long, default_value = "0.0.0.0:8080")]
        addr: SocketAddr,
    },

    /// Evaluate one JSON object and print the report. Exits 1 if it isn't allowed.
    Eval {
        /// Policy files or directories of them. Repeatable.
        #[arg(short, long = "policies", required = true)]
        policies: Vec<PathBuf>,

        /// The object to evaluate, as JSON. It's bound to `object` in expressions.
        #[arg(short, long)]
        json: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    match Cli::parse().command {
        Command::Serve { policies, addr } => {
            let provider = Provider::load(&policies)?;
            server::serve(provider, addr).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Eval { policies, json } => {
            let provider = Provider::load(&policies)?;
            let object = serde_json::from_str(&json).context("parsing --json")?;
            let report = provider.evaluate(&object);
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(if report.allowed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
    }
}

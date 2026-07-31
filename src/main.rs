//! gm-kms main binary entry point

use clap::Parser;
use std::path::PathBuf;

mod cmd;

#[derive(Parser, Debug)]
#[command(name = "gm-kms")]
#[command(about = "GM/KMS - Key Management System", long_about = None)]
struct Cli {
    /// Config file path
    #[arg(short, long, default_value = "kms.toml")]
    config: PathBuf,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Run as server
    #[arg(short, long)]
    server: bool,

    /// REST API port
    #[arg(long, default_value = "8080")]
    rest_port: u16,

    /// gRPC port
    #[arg(long, default_value = "9090")]
    grpc_port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.server {
        cmd::server::run(
            cli.config.to_str().unwrap_or("kms.toml"),
            cli.rest_port,
            cli.grpc_port,
        )
        .await?;
    } else {
        cmd::cli::run(cli.config).await?;
    }

    Ok(())
}

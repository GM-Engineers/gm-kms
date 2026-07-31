//! CLI command - interactive command line interface

use anyhow::Result;
use std::path::Path;

pub async fn run(_config_path: impl AsRef<Path>) -> Result<()> {
    println!("GM/KMS CLI");
    println!("==========");
    println!("Run with --server to start the server.");
    println!("CLI mode not yet implemented - use REST/gRPC API.");

    Ok(())
}

use clap::{Parser, Subcommand};
use seetle::{Algorithm, Bindings, KeyUsage, KeyOrIdentifier, HardwareBound};
use seetle::config::load_config;
use seetle::tui::run_tui;
use seetle::init::setup_seetle;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "seetle-cli")]
#[command(author = "Brave Experiments")]
#[command(version = "0.1.0")]
#[command(about = "CLI tool for hardware-backed key management", long_about = None)]
struct Cli {
    /// Directory to store key metadata
    #[arg(short, long)]
    storage_dir: Option<PathBuf>,

    /// Storage wrapper type: 'keyring' (default), 'tpm', or 'none'
    #[arg(short = 'w', long, value_parser = ["keyring", "tpm", "none"])]
    storage_wrapper: Option<String>,

    /// Root backend for XHD: 'keyring' (default), 'tpm', or 'mock'
    #[arg(short = 'r', long, value_parser = ["keyring", "tpm", "mock"])]
    root_backend: Option<String>,

    /// TPM TCTI device configuration (e.g. 'device:/dev/tpmrm0' or 'tabrmd:')
    #[arg(long)]
    tpm_device: Option<String>,

    /// Non-interactive mode: show command list instead of TUI when no subcommand is provided
    #[arg(short = 'T', long)]
    no_tui: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new key
    GenerateKey {
        /// Identifier for the new key
        #[arg(short, long)]
        identifier: String,
        /// Algorithm to use: 'Ed25519' (default), 'ECDSA', 'AES-GCM'
        #[arg(short, long, default_value = "Ed25519")]
        algorithm: String,
        /// XHD parameters for derivation, format 'XHD:Context:Account:Index:Scheme'
        /// e.g. 'XHD:Address:0:0:Peikert'
        #[arg(long)]
        xhd_params: Option<String>,
    },
    /// Sign data using a key
    Sign {
        /// Identifier of the key to use
        #[arg(short, long)]
        identifier: String,
        /// Data to sign (as a string)
        #[arg(short, long)]
        data: String,
        /// Algorithm name
        #[arg(short, long, default_value = "Ed25519")]
        algorithm: String,
    },
    /// Verify a signature
    Verify {
        /// Identifier of the key to use
        #[arg(short, long)]
        identifier: String,
        /// Data that was signed
        #[arg(short, long)]
        data: String,
        /// Signature (as hex string)
        #[arg(short, long)]
        signature: String,
        /// Algorithm name
        #[arg(short, long, default_value = "Ed25519")]
        algorithm: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tui_logger::init_logger(log::LevelFilter::Info).unwrap();
    tui_logger::set_default_level(log::LevelFilter::Info);

    let cli = Cli::parse();

    // If no command is provided, we either show the TUI or the command list
    if cli.command.is_none() {
        if cli.no_tui {
            use clap::CommandFactory;
            Cli::command().print_help()?;
            println!("\n\nCommands List:");
            for command in Cli::command().get_subcommands() {
                println!("  - {}", command.get_name());
            }
            return Ok(());
        } else {
            return run_tui().await;
        }
    }

    let mut config = load_config();
    if let Some(dir) = cli.storage_dir { config.storage_dir = dir; }
    if let Some(wrapper) = cli.storage_wrapper { config.storage_wrapper = wrapper; }
    if let Some(root) = cli.root_backend { config.root_backend = root; }
    if let Some(device) = cli.tpm_device { config.tpm_device = Some(device); }

    let seetle = setup_seetle(&config).await?;

    // 6. Execute commands
    match cli.command.unwrap() {
        Commands::GenerateKey { identifier, algorithm, xhd_params } => {
            let alg = if let Some(params) = xhd_params {
                Algorithm::Ed25519 { name: params }
            } else if algorithm == "Ed25519" {
                Algorithm::Ed25519 { name: "XHD:Address:0:0:Peikert".into() }
            } else {
                return Err(format!("Algorithm {} not yet supported for direct XHD generation via this CLI without xhd-params", algorithm).into());
            };

            let result = seetle.generate_key(
                alg,
                false,
                Some(Bindings {
                    identifier: identifier.clone(),
                    hardware_bound: HardwareBound::Yes,
                    ..Default::default()
                }),
                vec![KeyUsage::Sign, KeyUsage::Verify]
            ).await?;

            println!("Key generated: {:?}", result);
        },
        Commands::Sign { identifier, data, algorithm } => {
            let alg = match algorithm.as_str() {
                "Ed25519" => Algorithm::Ed25519 { name: "Ed25519".into() },
                _ => return Err(format!("Algorithm {} not supported for signing", algorithm).into()),
            };

            let signature = seetle.sign(
                alg,
                KeyOrIdentifier::Identifier(identifier),
                data.into_bytes()
            ).await?;

            println!("Signature (hex): {}", hex::encode(signature));
        },
        Commands::Verify { identifier, data, signature, algorithm } => {
            let alg = match algorithm.as_str() {
                "Ed25519" => Algorithm::Ed25519 { name: "Ed25519".into() },
                _ => return Err(format!("Algorithm {} not supported for verification", algorithm).into()),
            };

            let signature_bytes = hex::decode(signature)?;
            let verified = seetle.verify(
                alg,
                KeyOrIdentifier::Identifier(identifier),
                signature_bytes,
                data.into_bytes()
            ).await?;

            println!("Verified: {}", verified);
        }
    }

    Ok(())
}

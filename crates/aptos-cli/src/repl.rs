//! Interactive REPL with encrypted credential support.
//!
//! The REPL provides an interactive command loop where credentials are
//! decrypted once at session start and held in memory. Commands that need
//! a signer can reference a stored credential by alias instead of passing
//! a raw private key.

use anyhow::{Context, Result, bail};
use crossterm::style::{Attribute, Color, ResetColor, SetAttribute, SetForegroundColor};
use rustyline::DefaultEditor;
use std::io::Write;

use crate::common::{GlobalOpts, KeyType, NetworkArg};
use crate::credentials::{self, Vault};
use crate::output;

/// Session state for the REPL.
struct Session {
    vault: Option<Vault>,
    global: GlobalOpts,
    /// Currently selected credential alias for signing operations.
    active_account: Option<String>,
}

impl Session {
    fn new(global: GlobalOpts) -> Self {
        Session {
            vault: None,
            global,
            active_account: None,
        }
    }
}

/// Run the interactive REPL.
pub async fn run_repl(global: GlobalOpts) -> Result<()> {
    let mut session = Session::new(global);

    print_banner();

    // Try to unlock vault if one exists
    if credentials::vault_exists() {
        output::print_info("Encrypted vault found. Enter your password to unlock.");
        unlock_vault(&mut session)?;
    } else {
        output::print_dim("No credential vault found.");
        output::print_dim("Use `credential init` to create one, or continue without.");
    }

    println!();
    print_repl_help();

    let mut rl = DefaultEditor::new().context("failed to initialise line editor")?;

    // Try to load history
    let history_path = dirs::home_dir().map(|h| h.join(".aptos-sdk-cli").join("repl_history"));
    if let Some(ref hp) = history_path {
        let _ = rl.load_history(hp);
    }

    loop {
        let prompt = build_prompt(&session);
        let line = match rl.readline(&prompt) {
            Ok(line) => line,
            Err(
                rustyline::error::ReadlineError::Interrupted | rustyline::error::ReadlineError::Eof,
            ) => {
                break;
            }
            Err(e) => {
                output::print_error(&format!("{e}"));
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let _ = rl.add_history_entry(trimmed);

        match handle_line(trimmed, &mut session).await {
            Ok(ShouldContinue::Yes) => {}
            Ok(ShouldContinue::Quit) => break,
            Err(e) => {
                output::print_error(&format!("{e:#}"));
            }
        }
    }

    // Save history
    if let Some(ref hp) = history_path {
        if let Some(parent) = hp.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = rl.save_history(hp);
    }

    let mut stdout = std::io::stdout();
    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
    println!("Goodbye.");
    let _ = crossterm::execute!(stdout, ResetColor);
    Ok(())
}

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

fn print_banner() {
    let mut stdout = std::io::stdout();
    println!();

    let _ = crossterm::execute!(
        stdout,
        SetForegroundColor(Color::Cyan),
        SetAttribute(Attribute::Bold)
    );
    println!("    ╔══════════════════════════════════════════╗");
    println!("    ║                                          ║");
    println!("    ║          Aptos SDK CLI  ·  REPL          ║");
    println!("    ║                                          ║");
    println!("    ╚══════════════════════════════════════════╝");
    let _ = crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));

    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
    println!("     Encrypted credentials · Interactive shell");
    let _ = crossterm::execute!(stdout, ResetColor);
    println!();
}

// ---------------------------------------------------------------------------
// Prompt
// ---------------------------------------------------------------------------

fn build_prompt(session: &Session) -> String {
    let network = match session.global.network {
        NetworkArg::Mainnet => "mainnet",
        NetworkArg::Testnet => "testnet",
        NetworkArg::Devnet => "devnet",
        NetworkArg::Local => "local",
    };

    // Use ANSI codes directly in the prompt string.
    // Wrap color escapes in \x01..\x02 so rustyline doesn't count them
    // towards the visible prompt width (prevents cursor misalignment).
    let net_color = match session.global.network {
        NetworkArg::Mainnet => "\x1b[32m", // green
        NetworkArg::Testnet => "\x1b[33m", // yellow
        NetworkArg::Devnet => "\x1b[36m",  // cyan
        NetworkArg::Local => "\x1b[35m",   // magenta
    };
    let reset = "\x1b[0m";
    let bold = "\x1b[1m";
    let cyan = "\x1b[36m";
    let magenta = "\x1b[35m";
    let dim = "\x1b[2m";

    let account_part = if let Some(ref alias) = session.active_account {
        format!("{dim}:{reset}{magenta}{bold}{alias}{reset}")
    } else {
        String::new()
    };

    let vault_indicator = if session.vault.is_some() {
        format!("{dim}🔓{reset} ")
    } else {
        String::new()
    };

    format!(
        "{vault_indicator}{cyan}{bold}aptos{reset}{dim}({reset}{net_color}{bold}{network}{reset}{account_part}{dim}){reset}{cyan}{bold}>{reset} "
    )
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

enum ShouldContinue {
    Yes,
    Quit,
}

async fn handle_line(line: &str, session: &mut Session) -> Result<ShouldContinue> {
    let tokens = shellwords::split(line).context("invalid quoting")?;
    if tokens.is_empty() {
        return Ok(ShouldContinue::Yes);
    }

    let cmd = tokens[0].as_str();
    let args = &tokens[1..];

    match cmd {
        "quit" | "exit" | "q" => return Ok(ShouldContinue::Quit),
        "help" | "?" => print_repl_help(),
        "credential" | "cred" => handle_credential(args, session)?,
        "use" => handle_use(args, session)?,
        "whoami" => handle_whoami(session)?,
        "network" => handle_network(args, session)?,
        "account" => handle_sdk_command(cmd, args, session).await?,
        "key" => handle_sdk_command(cmd, args, session).await?,
        "move" => handle_sdk_command(cmd, args, session).await?,
        "transaction" | "tx" => handle_sdk_command("transaction", args, session).await?,
        "info" => handle_sdk_command(cmd, args, session).await?,
        _ => {
            output::print_error(&format!(
                "Unknown command: `{cmd}`. Type `help` for available commands."
            ));
        }
    }

    Ok(ShouldContinue::Yes)
}

// ---------------------------------------------------------------------------
// Credential commands
// ---------------------------------------------------------------------------

fn handle_credential(args: &[String], session: &mut Session) -> Result<()> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("help");

    match sub {
        "init" => {
            if credentials::vault_exists() {
                bail!("Vault already exists. Use `credential unlock` to open it.");
            }
            let password = credentials::prompt_password("Create vault password: ")?;
            let confirm = credentials::prompt_password("Confirm password: ")?;
            if password != confirm {
                bail!("Passwords do not match.");
            }
            if password.len() < 8 {
                bail!("Password must be at least 8 characters.");
            }
            let vault = Vault::create(&password)?;
            output::print_success("Vault created and unlocked");
            session.vault = Some(vault);
        }
        "unlock" => {
            unlock_vault(session)?;
        }
        "lock" => {
            session.vault = None;
            session.active_account = None;
            output::print_success("Vault locked — credentials cleared from memory");
        }
        "add" => {
            let vault = session
                .vault
                .as_mut()
                .context("vault not unlocked. Run `credential unlock` first")?;

            let alias = args.get(1).context(
                "usage: credential add <alias> [key_type]\n  key_type: ed25519 (default), secp256k1, secp256r1",
            )?;

            let key_type = if let Some(kt) = args.get(2) {
                match kt.as_str() {
                    "ed25519" => KeyType::Ed25519,
                    "secp256k1" => KeyType::Secp256k1,
                    "secp256r1" => KeyType::Secp256r1,
                    _ => bail!("unknown key type: {kt}"),
                }
            } else {
                KeyType::Ed25519
            };

            let private_key = credentials::prompt_password("Private key (hex, will not echo): ")?;

            vault.add(alias, &key_type, private_key.trim())?;

            // Show address
            if let Some(cred) = vault.get(alias) {
                let account = cred.to_cli_account()?;
                output::print_success(&format!("Added '{alias}' → {}", account.address()));
            }
        }
        "remove" | "rm" => {
            let vault = session.vault.as_mut().context("vault not unlocked")?;
            let alias = args.get(1).context("usage: credential remove <alias>")?;
            vault.remove(alias)?;
            if session.active_account.as_deref() == Some(alias.as_str()) {
                session.active_account = None;
            }
            output::print_success(&format!("Removed '{alias}'"));
        }
        "list" | "ls" => {
            let vault = session.vault.as_ref().context("vault not unlocked")?;
            let entries = vault.list();
            if entries.is_empty() {
                output::print_dim(
                    "No credentials stored. Use `credential add <alias>` to add one.",
                );
            } else {
                output::print_header(&format!("Stored Credentials ({})", entries.len()));
                let mut stdout = std::io::stdout();
                for (alias, key_type, address) in &entries {
                    let is_active = session.active_account.as_deref() == Some(*alias);

                    print!("    ");
                    if is_active {
                        let _ = crossterm::execute!(
                            stdout,
                            SetForegroundColor(Color::Green),
                            SetAttribute(Attribute::Bold)
                        );
                        print!("▸ ");
                    } else {
                        print!("  ");
                    }
                    let _ = crossterm::execute!(
                        stdout,
                        SetForegroundColor(Color::White),
                        SetAttribute(Attribute::Bold)
                    );
                    print!("{alias:16}");
                    let _ = crossterm::execute!(stdout, SetAttribute(Attribute::Reset));

                    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
                    print!("{key_type:12?}");
                    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::Cyan));
                    print!("{address}");

                    if is_active {
                        let _ = crossterm::execute!(stdout, SetForegroundColor(Color::Green));
                        print!("  (active)");
                    }
                    let _ = crossterm::execute!(stdout, ResetColor);
                    println!();
                }
            }
        }
        "change-password" => {
            let vault = session.vault.as_ref().context("vault not unlocked")?;

            let new_password = credentials::prompt_password("New password: ")?;
            let confirm = credentials::prompt_password("Confirm new password: ")?;
            if new_password != confirm {
                bail!("Passwords do not match.");
            }
            if new_password.len() < 8 {
                bail!("Password must be at least 8 characters.");
            }

            // Collect existing credentials (alias, key_type, private_key_hex)
            let existing: Vec<(String, KeyType, String)> = vault
                .list()
                .iter()
                .filter_map(|(alias, _kt, _addr)| {
                    vault.get(alias).map(|c| {
                        (
                            alias.to_string(),
                            c.key_type.clone(),
                            c.private_key_hex().to_string(),
                        )
                    })
                })
                .collect();

            // Delete and recreate with new password
            let vault_path = Vault::default_path()?;
            std::fs::remove_file(&vault_path).context("failed to remove old vault")?;
            let mut new_vault = Vault::create(&new_password)?;

            // Re-add all credentials
            for (alias, key_type, key_hex) in &existing {
                new_vault.add(alias, key_type, key_hex)?;
            }

            let count = new_vault.len();
            session.vault = Some(new_vault);
            output::print_success(&format!(
                "Password changed. {count} credential(s) re-encrypted."
            ));
        }
        _ => {
            print_credential_help();
        }
    }
    Ok(())
}

fn print_credential_help() {
    let mut stdout = std::io::stdout();

    output::print_header("Credential Commands");

    let commands = [
        ("init", "Create a new encrypted vault"),
        ("unlock", "Unlock an existing vault"),
        ("lock", "Lock the vault (clear from memory)"),
        (
            "add <alias> [type]",
            "Add a private key (prompted securely)",
        ),
        ("remove <alias>", "Remove a stored credential"),
        ("list", "List all stored credentials"),
        ("change-password", "Change the vault password"),
    ];

    for (cmd, desc) in &commands {
        print!("    ");
        let _ = crossterm::execute!(
            stdout,
            SetForegroundColor(Color::Cyan),
            SetAttribute(Attribute::Bold)
        );
        print!("credential {cmd:22}");
        let _ = crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));
        let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
        println!("{desc}");
        let _ = crossterm::execute!(stdout, ResetColor);
    }
    println!();
}

fn unlock_vault(session: &mut Session) -> Result<()> {
    let password = credentials::prompt_password("Vault password: ")?;
    let mut stdout = std::io::stdout();
    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
    print!("  Deriving key...");
    let _ = stdout.flush();
    let vault = Vault::open(&password)?;
    println!(" done.");
    let _ = crossterm::execute!(stdout, ResetColor);
    let count = vault.len();
    session.vault = Some(vault);
    output::print_success(&format!("Vault unlocked ({count} credential(s))"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Session commands
// ---------------------------------------------------------------------------

fn handle_use(args: &[String], session: &mut Session) -> Result<()> {
    let alias = args.first().context(
        "usage: use <alias>  — set the active account for signing\n       use none     — clear active account",
    )?;

    if alias == "none" {
        session.active_account = None;
        output::print_info("Active account cleared.");
        return Ok(());
    }

    let vault = session.vault.as_ref().context("vault not unlocked")?;

    let cred = vault.get(alias).context(format!(
        "no credential '{alias}'. Run `credential list` to see available."
    ))?;

    let account = cred.to_cli_account()?;
    output::print_success(&format!("Active account: {alias} ({})", account.address()));
    session.active_account = Some(alias.clone());
    Ok(())
}

fn handle_whoami(session: &Session) -> Result<()> {
    match &session.active_account {
        Some(alias) => {
            let vault = session.vault.as_ref().context("vault not unlocked")?;
            if let Some(cred) = vault.get(alias) {
                let account = cred.to_cli_account()?;
                let mut stdout = std::io::stdout();
                output::print_header("Active Identity");
                // Alias
                let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
                print!("    Alias:    ");
                let _ = crossterm::execute!(
                    stdout,
                    SetForegroundColor(Color::Magenta),
                    SetAttribute(Attribute::Bold)
                );
                println!("{alias}");
                let _ = crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));
                // Address
                let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
                print!("    Address:  ");
                let _ = crossterm::execute!(stdout, SetForegroundColor(Color::Cyan));
                println!("{}", account.address());
                let _ = crossterm::execute!(stdout, ResetColor);
                // Key type
                let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
                print!("    Key type: ");
                let _ = crossterm::execute!(stdout, SetForegroundColor(Color::White));
                println!("{:?}", cred.key_type);
                let _ = crossterm::execute!(stdout, ResetColor);
            }
        }
        None => {
            output::print_dim("No active account. Use `use <alias>` to set one.");
        }
    }
    Ok(())
}

fn handle_network(args: &[String], session: &mut Session) -> Result<()> {
    if let Some(net) = args.first() {
        session.global.network = match net.as_str() {
            "mainnet" => NetworkArg::Mainnet,
            "testnet" => NetworkArg::Testnet,
            "devnet" => NetworkArg::Devnet,
            "local" => NetworkArg::Local,
            _ => bail!("unknown network: {net}. Options: mainnet, testnet, devnet, local"),
        };
        output::print_success(&format!("Switched to {net}"));
    } else {
        let mut stdout = std::io::stdout();
        let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
        print!("  Current network: ");
        let _ = crossterm::execute!(
            stdout,
            SetForegroundColor(Color::Yellow),
            SetAttribute(Attribute::Bold)
        );
        println!("{:?}", session.global.network);
        let _ = crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));
        output::print_dim("usage: network <mainnet|testnet|devnet|local>");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SDK command passthrough
// ---------------------------------------------------------------------------

/// Handle SDK commands. If a command needs `--private-key`, and none is supplied
/// but an active account is set, we inject the stored credential.
async fn handle_sdk_command(cmd: &str, args: &[String], session: &mut Session) -> Result<()> {
    // Build a clap-style argument vector: ["aptos-sdk-cli", <cmd>, ...args]
    let mut argv: Vec<String> = vec!["aptos-sdk-cli".to_string(), cmd.to_string()];
    argv.extend_from_slice(args);

    // Inject credentials if needed
    let needs_key = argv.iter().any(|a| {
        a == "run" || a == "publish" || a == "build-publish" || a == "transfer" || a == "fund"
    });
    let has_key = argv.iter().any(|a| a == "--private-key");

    if needs_key
        && !has_key
        && let Some(ref alias) = session.active_account
        && let Some(vault) = &session.vault
        && let Some(cred) = vault.get(alias)
    {
        inject_credential(&mut argv, cred)?;
    }

    // Also inject global options
    if !argv.iter().any(|a| a == "--network") && session.global.node_url.is_none() {
        argv.push("--network".to_string());
        argv.push(format!("{:?}", session.global.network).to_lowercase());
    }
    if let Some(ref url) = session.global.node_url
        && !argv.iter().any(|a| a == "--node-url")
    {
        argv.push("--node-url".to_string());
        argv.push(url.clone());
    }
    if let Some(ref key) = session.global.api_key
        && !argv.iter().any(|a| a == "--api-key")
    {
        argv.push("--api-key".to_string());
        argv.push(key.clone());
    }
    if session.global.json && !argv.iter().any(|a| a == "--json") {
        argv.push("--json".to_string());
    }

    // Parse and dispatch
    dispatch_command(&argv).await
}

fn inject_credential(argv: &mut Vec<String>, cred: &credentials::Credential) -> Result<()> {
    argv.push("--private-key".to_string());
    argv.push(cred.private_key_hex().to_string());

    let kt = match cred.key_type {
        KeyType::Ed25519 => "ed25519",
        KeyType::Secp256k1 => "secp256k1",
        KeyType::Secp256r1 => "secp256r1",
    };
    if !argv.iter().any(|a| a == "--key-type") {
        argv.push("--key-type".to_string());
        argv.push(kt.to_string());
    }

    Ok(())
}

async fn dispatch_command(argv: &[String]) -> Result<()> {
    use clap::Parser;

    let cli = crate::Cli::try_parse_from(argv).context("invalid command syntax")?;

    match cli.command {
        crate::Command::Account(cmd) => cmd.run(&cli.global).await,
        crate::Command::Key(cmd) => cmd.run(&cli.global),
        crate::Command::Move(cmd) => cmd.run(&cli.global).await,
        crate::Command::Transaction(cmd) => cmd.run(&cli.global).await,
        crate::Command::Info(cmd) => cmd.run(&cli.global).await,
        crate::Command::Repl => {
            output::print_dim("Already in REPL mode.");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------

fn print_repl_help() {
    let mut stdout = std::io::stdout();

    // Session commands
    let _ = crossterm::execute!(
        stdout,
        SetForegroundColor(Color::Cyan),
        SetAttribute(Attribute::Bold)
    );
    println!("  Session");
    let _ = crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));

    print_help_row(
        &mut stdout,
        "credential <sub>",
        "Manage encrypted credentials",
    );
    print_help_row(&mut stdout, "use <alias>", "Set active account for signing");
    print_help_row(&mut stdout, "use none", "Clear active account");
    print_help_row(&mut stdout, "whoami", "Show active account details");
    print_help_row(&mut stdout, "network <name>", "Switch network");

    println!();
    let _ = crossterm::execute!(
        stdout,
        SetForegroundColor(Color::Cyan),
        SetAttribute(Attribute::Bold)
    );
    println!("  Blockchain");
    let _ = crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));

    print_help_row(&mut stdout, "account <sub>", "Account operations");
    print_help_row(&mut stdout, "key <sub>", "Key management");
    print_help_row(
        &mut stdout,
        "move <sub>",
        "Move ops (compile, test, view, run, publish)",
    );
    print_help_row(&mut stdout, "tx <sub>", "Transaction operations");
    print_help_row(
        &mut stdout,
        "info <sub>",
        "Network info (ledger, gas, block)",
    );

    println!();
    let _ = crossterm::execute!(
        stdout,
        SetForegroundColor(Color::Cyan),
        SetAttribute(Attribute::Bold)
    );
    println!("  Other");
    let _ = crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));

    print_help_row(&mut stdout, "help", "Show this help");
    print_help_row(&mut stdout, "quit", "Exit the REPL");

    println!();
    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
    println!("  Tip: When an active account is set, signing commands auto-inject");
    println!("  the stored credential — no --private-key needed.");
    let _ = crossterm::execute!(stdout, ResetColor);
    println!();
}

fn print_help_row(stdout: &mut std::io::Stdout, cmd: &str, desc: &str) {
    let _ = crossterm::execute!(
        stdout,
        SetForegroundColor(Color::Yellow),
        SetAttribute(Attribute::Bold)
    );
    print!("    {cmd:24}");
    let _ = crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));
    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
    println!("{desc}");
    let _ = crossterm::execute!(stdout, ResetColor);
}

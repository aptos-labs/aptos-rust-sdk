//! Interactive REPL with encrypted credential support.
//!
//! The REPL provides an interactive command loop where credentials are
//! decrypted once at session start and held in memory. Commands that need
//! a signer can reference a stored credential by alias instead of passing
//! a raw private key.

use anyhow::{Context, Result, bail};
use aptos_sdk::account::{Ed25519Account, Secp256k1Account, Secp256r1Account};
use crossterm::style::{Attribute, Color, ResetColor, SetAttribute, SetForegroundColor};
use rustyline::DefaultEditor;
use std::io::Write;
use zeroize::Zeroize;

use crate::common::{GlobalOpts, KeyType, NetworkArg};
use crate::config::CliConfig;
use crate::credentials::{self, Vault};
use crate::output;

/// Session state for the REPL.
struct Session {
    vault: Option<Vault>,
    global: GlobalOpts,
    config: CliConfig,
    /// Currently selected credential alias for signing operations.
    active_account: Option<String>,
}

impl Session {
    fn new(global: GlobalOpts, config: CliConfig) -> Self {
        Session {
            vault: None,
            global,
            config,
            active_account: None,
        }
    }
}

/// Run the interactive REPL.
pub async fn run_repl(mut global: GlobalOpts) -> Result<()> {
    // Load persistent config and apply defaults to global opts
    let config = CliConfig::load().unwrap_or_default();
    apply_config_defaults(&mut global, &config);

    let mut session = Session::new(global, config);

    print_banner();

    // Onboarding: unlock existing vault or guide through first-time setup
    if credentials::vault_exists() {
        output::print_info("Encrypted vault found. Enter your password to unlock.");
        unlock_vault(&mut session)?;
    } else {
        run_onboarding(&mut session)?;
    }

    // Auto-activate default account from config
    if session.active_account.is_none()
        && let Some(ref alias) = session.config.default_account
        && let Some(ref vault) = session.vault
        && vault.get(alias).is_some()
    {
        session.active_account = Some(alias.clone());
        output::print_dim(&format!("Auto-activated account '{alias}' from config"));
    }

    println!();
    print_repl_help();

    let mut rl = DefaultEditor::new().context("failed to initialise line editor")?;

    // Try to load history
    let history_path =
        dirs::home_dir().map(|h| h.join(".aptos").join("config").join("repl_history"));
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

        // Never persist sensitive data to history
        if !contains_secret(trimmed) {
            let _ = rl.add_history_entry(trimmed);
        }

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

        // Set restrictive permissions on the history file (Unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(hp, std::fs::Permissions::from_mode(0o600));
        }
    }

    let mut stdout = std::io::stdout();
    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
    println!("Goodbye.");
    let _ = crossterm::execute!(stdout, ResetColor);
    Ok(())
}

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

/// Apply saved config defaults to global opts (CLI flags take precedence).
fn apply_config_defaults(global: &mut GlobalOpts, config: &CliConfig) {
    // Only apply network from config if the user didn't pass --network on the
    // command line (clap default is "mainnet", so we can't easily distinguish;
    // we apply if config has a value).
    if let Some(ref net) = config.network
        && let Some(parsed) = parse_network_str(net)
    {
        global.network = parsed;
    }
    if global.node_url.is_none()
        && let Some(ref url) = config.node_url
    {
        global.node_url = Some(url.clone());
    }
    if global.api_key.is_none()
        && let Some(ref key) = config.api_key
    {
        global.api_key = Some(key.clone());
    }
    if let Some(json) = config.json_output {
        // Only override if user did not pass --json on CLI
        if !global.json {
            global.json = json;
        }
    }
}

pub(crate) fn parse_network_str(s: &str) -> Option<NetworkArg> {
    match s {
        "mainnet" => Some(NetworkArg::Mainnet),
        "testnet" => Some(NetworkArg::Testnet),
        "devnet" => Some(NetworkArg::Devnet),
        "local" => Some(NetworkArg::Local),
        _ => None,
    }
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
        "config" => handle_config(args, session)?,
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
            validate_password_strength(&password)?;
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
        "generate" | "gen" => {
            let alias = args.get(1).context(
                "usage: credential generate <alias> [key_type]\n  key_type: ed25519 (default), secp256k1, secp256r1",
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

            generate_and_store(session, alias, &key_type)?;

            // Auto-set as active if none set
            if session.active_account.is_none() {
                session.active_account = Some(alias.to_string());
                output::print_info(&format!("Active account set to '{alias}'"));
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
        "import" => {
            let vault = session
                .vault
                .as_mut()
                .context("vault not unlocked. Run `credential unlock` first")?;
            import_legacy_profiles(vault)?;
        }
        "change-password" => {
            let vault = session.vault.as_ref().context("vault not unlocked")?;

            let new_password = credentials::prompt_password("New password: ")?;
            let confirm = credentials::prompt_password("Confirm new password: ")?;
            if new_password != confirm {
                bail!("Passwords do not match.");
            }
            validate_password_strength(&new_password)?;

            // Collect alias/key_type pairs only (no secrets yet)
            let entries: Vec<(String, KeyType)> = vault
                .list()
                .iter()
                .map(|(alias, _kt, _addr)| {
                    let kt = vault
                        .get(alias)
                        .map(|c| c.key_type.clone())
                        .unwrap_or(KeyType::Ed25519);
                    (alias.to_string(), kt)
                })
                .collect();

            // Delete and recreate with new password
            let vault_path = Vault::default_path()?;
            std::fs::remove_file(&vault_path).context("failed to remove old vault")?;
            let mut new_vault = Vault::create(&new_password)?;

            // Re-encrypt credentials one at a time, zeroizing each key after use
            let old_vault = session.vault.as_ref().unwrap();
            for (alias, key_type) in &entries {
                if let Some(cred) = old_vault.get(alias) {
                    let mut key_hex = cred.private_key_hex().to_string();
                    new_vault.add(alias, key_type, &key_hex)?;
                    key_hex.zeroize();
                }
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
            "generate <alias> [type]",
            "Generate a new keypair and store it",
        ),
        ("add <alias> [type]", "Import an existing private key"),
        ("import", "Import from ~/.aptos/config.yaml"),
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
    const MAX_ATTEMPTS: u32 = 5;
    let mut attempts = 0u32;

    loop {
        let password = credentials::prompt_password("Vault password: ")?;
        let mut stdout = std::io::stdout();
        let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
        print!("  Deriving key...");
        let _ = stdout.flush();

        match Vault::open(&password) {
            Ok(vault) => {
                println!(" done.");
                let _ = crossterm::execute!(stdout, ResetColor);
                let count = vault.len();
                session.vault = Some(vault);
                output::print_success(&format!("Vault unlocked ({count} credential(s))"));
                return Ok(());
            }
            Err(_) => {
                println!();
                let _ = crossterm::execute!(stdout, ResetColor);
                attempts += 1;
                if attempts >= MAX_ATTEMPTS {
                    bail!(
                        "Too many failed attempts ({MAX_ATTEMPTS}). Please restart the REPL to try again."
                    );
                }
                // Exponential backoff: 1s, 2s, 4s, 8s...
                let delay = std::time::Duration::from_secs(1 << (attempts - 1));
                output::print_error(&format!(
                    "Wrong password. {remaining} attempt(s) remaining. Waiting {delay}s...",
                    remaining = MAX_ATTEMPTS - attempts,
                    delay = delay.as_secs()
                ));
                std::thread::sleep(delay);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Onboarding
// ---------------------------------------------------------------------------

/// Guided first-time setup: create vault, generate a key, set it active.
fn run_onboarding(session: &mut Session) -> Result<()> {
    let mut stdout = std::io::stdout();

    let _ = crossterm::execute!(
        stdout,
        SetForegroundColor(Color::Cyan),
        SetAttribute(Attribute::Bold)
    );
    println!("  Welcome! Let's get you set up.");
    let _ = crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));
    println!();
    output::print_dim("This will create an encrypted vault to store your keys.");
    println!();

    // Detect existing Aptos CLI config
    let has_legacy = crate::import::legacy_config_exists();
    if has_legacy {
        let _ = crossterm::execute!(
            stdout,
            SetForegroundColor(Color::Cyan),
            SetAttribute(Attribute::Bold)
        );
        println!("  Detected existing Aptos CLI config at ~/.aptos/config.yaml");
        let _ = crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));
        output::print_dim("Your existing profiles can be imported into the encrypted vault.");
        println!();
    }

    // Step 1: Create vault password
    let _ = crossterm::execute!(
        stdout,
        SetForegroundColor(Color::Yellow),
        SetAttribute(Attribute::Bold)
    );
    println!("  Step 1: Create a vault password");
    let _ = crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));
    output::print_dim("This password encrypts your private keys on disk.");
    println!();

    let password = loop {
        let pw =
            credentials::prompt_password("  Vault password (min 12 chars, letters + numbers): ")?;
        if let Err(e) = validate_password_strength(&pw) {
            output::print_error(&format!("{e} Try again."));
            continue;
        }
        let confirm = credentials::prompt_password("  Confirm password: ")?;
        if pw != confirm {
            output::print_error("Passwords do not match. Try again.");
            continue;
        }
        break pw;
    };

    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
    print!("  Deriving encryption key...");
    let _ = stdout.flush();
    let vault = Vault::create(&password)?;
    println!(" done.");
    let _ = crossterm::execute!(stdout, ResetColor);
    output::print_success("Vault created");
    session.vault = Some(vault);

    println!();

    // Step 2: Import existing profiles or generate a new one
    if has_legacy {
        let _ = crossterm::execute!(
            stdout,
            SetForegroundColor(Color::Yellow),
            SetAttribute(Attribute::Bold)
        );
        println!("  Step 2: Import existing profiles");
        let _ = crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));
        println!();

        let answer = prompt_line("  Import profiles from ~/.aptos/config.yaml? [Y/n]: ")?;
        let answer = answer.trim().to_lowercase();

        if answer.is_empty() || answer == "y" || answer == "yes" {
            let vault = session.vault.as_mut().unwrap();
            import_legacy_profiles(vault)?;

            // Set the network from the "default" profile if available
            if let Ok(config) = crate::import::load_legacy_config() {
                apply_legacy_defaults(&config, session);
            }

            // Set the active account to "default" if it was imported, otherwise
            // pick the first available profile.
            let vault = session.vault.as_ref().unwrap();
            let chosen: Option<String> = if vault.get("default").is_some() {
                Some("default".to_string())
            } else {
                vault.list().first().map(|(alias, _, _)| alias.to_string())
            };

            if let Some(ref alias) = chosen {
                session.active_account = Some(alias.clone());
                session.config.default_account = Some(alias.clone());
                session.config.save()?;
                output::print_success(&format!("Active account set to '{alias}'"));
            }
        } else {
            output::print_dim("Skipped import. You can run `credential import` later.");
            onboarding_generate(session)?;
        }
    } else {
        let _ = crossterm::execute!(
            stdout,
            SetForegroundColor(Color::Yellow),
            SetAttribute(Attribute::Bold)
        );
        println!("  Step 2: Generate your first account");
        let _ = crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));
        println!();

        onboarding_generate(session)?;
    }

    println!();
    let _ = crossterm::execute!(
        stdout,
        SetForegroundColor(Color::Green),
        SetAttribute(Attribute::Bold)
    );
    println!("  You're all set! Your account is ready to use.");
    let _ = crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));
    output::print_dim("Fund it on testnet with: account fund --address <your-address>");
    output::print_dim("Tip: use `config set network testnet` to default to testnet.");

    Ok(())
}

/// Generate a new keypair and store it in the vault.
/// Returns the address string.
fn generate_and_store(session: &mut Session, alias: &str, key_type: &KeyType) -> Result<String> {
    let vault = session.vault.as_mut().context("vault not unlocked")?;

    let (private_key_hex, address, public_key) = match key_type {
        KeyType::Ed25519 => {
            let account = Ed25519Account::generate();
            (
                hex::encode(account.private_key().to_bytes()),
                account.address().to_string(),
                account.public_key().to_string(),
            )
        }
        KeyType::Secp256k1 => {
            let account = Secp256k1Account::generate();
            (
                hex::encode(account.private_key().to_bytes()),
                account.address().to_string(),
                account.public_key().to_string(),
            )
        }
        KeyType::Secp256r1 => {
            let account = Secp256r1Account::generate();
            (
                hex::encode(account.private_key().to_bytes()),
                account.address().to_string(),
                account.public_key().to_string(),
            )
        }
    };

    vault.add(alias, key_type, &private_key_hex)?;

    let mut stdout = std::io::stdout();

    output::print_success(&format!("Generated {key_type:?} keypair '{alias}'"));

    // Address
    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
    print!("    Address:    ");
    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::Cyan));
    println!("{address}");
    let _ = crossterm::execute!(stdout, ResetColor);

    // Public key
    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
    print!("    Public Key: ");
    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::White));
    println!("{public_key}");
    let _ = crossterm::execute!(stdout, ResetColor);

    // Key type
    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
    print!("    Key Type:   ");
    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::White));
    println!("{key_type:?}");
    let _ = crossterm::execute!(stdout, ResetColor);

    output::print_dim("Private key encrypted and stored in vault.");

    Ok(address)
}

/// Prompt for a single line of input (with echo).
fn prompt_line(prompt: &str) -> Result<String> {
    let mut stdout = std::io::stdout();
    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
    print!("{prompt}");
    let _ = crossterm::execute!(stdout, ResetColor);
    let _ = stdout.flush();
    let mut buf = String::new();
    std::io::stdin()
        .read_line(&mut buf)
        .context("failed to read input")?;
    Ok(buf.trim().to_string())
}

/// Onboarding helper: generate a new keypair and set as active.
fn onboarding_generate(session: &mut Session) -> Result<()> {
    let alias = prompt_line("  Account name (e.g. \"default\"): ")?;
    let alias = alias.trim();
    let alias = if alias.is_empty() { "default" } else { alias };

    generate_and_store(session, alias, &KeyType::Ed25519)?;

    session.active_account = Some(alias.to_string());
    session.config.default_account = Some(alias.to_string());
    session.config.save()?;
    output::print_success(&format!("Active account set to '{alias}'"));
    Ok(())
}

/// Apply defaults from a legacy Aptos CLI config to the session.
///
/// Reads the "default" profile for network. Also checks all profiles for a
/// consistent `rest_url` and sets `node_url` if appropriate.
fn apply_legacy_defaults(legacy: &crate::import::LegacyConfig, session: &mut Session) {
    // Use the "default" profile's network if available
    if let Some(default_profile) = legacy.profiles.get("default") {
        if let Some(ref network) = default_profile.network {
            let net_lower = network.to_lowercase();
            if session.config.network.is_none() {
                match net_lower.as_str() {
                    "mainnet" | "testnet" | "devnet" | "local" => {
                        session.config.network = Some(network.clone());
                        output::print_dim(&format!(
                            "  Set default network to {network} (from legacy config)"
                        ));
                    }
                    _ => {}
                }
            }
        }

        // If the default profile has a rest_url that isn't the standard one,
        // set it as node_url so the user doesn't have to.
        if let Some(ref url) = default_profile.rest_url
            && session.config.node_url.is_none()
            && is_custom_node_url(url)
        {
            session.config.node_url = Some(url.clone());
            output::print_dim(&format!("  Set node URL to {url} (from legacy config)"));
        }
    }

    // Save the updated config
    let _ = session.config.save();
}

/// Check if a node URL is a non-default (custom) URL.
fn is_custom_node_url(url: &str) -> bool {
    let standard = [
        "https://fullnode.mainnet.aptoslabs.com",
        "https://fullnode.testnet.aptoslabs.com",
        "https://fullnode.devnet.aptoslabs.com",
        "http://localhost:8080",
    ];
    !standard.iter().any(|s| url.starts_with(s))
}

// ---------------------------------------------------------------------------
// Import from legacy Aptos CLI
// ---------------------------------------------------------------------------

/// Import profiles from the legacy `~/.aptos/config.yaml` into the vault.
fn import_legacy_profiles(vault: &mut Vault) -> Result<()> {
    use crate::import;

    if !import::legacy_config_exists() {
        output::print_dim("No legacy Aptos CLI config found at ~/.aptos/config.yaml");
        return Ok(());
    }

    let config = import::load_legacy_config()?;
    let profiles = import::extract_importable_profiles(&config);

    if profiles.is_empty() {
        output::print_dim("No importable profiles found (profiles need a private key).");
        return Ok(());
    }

    let mut imported = 0u32;
    let mut skipped = 0u32;

    for profile in &profiles {
        if vault.get(&profile.alias).is_some() {
            output::print_dim(&format!("  Skipping '{}' (already exists)", profile.alias));
            skipped += 1;
            continue;
        }

        match vault.add(&profile.alias, &profile.key_type, &profile.private_key_hex) {
            Ok(()) => {
                let account =
                    crate::common::load_account(&profile.private_key_hex, &profile.key_type)?;
                let net = profile.network.as_deref().unwrap_or("?");
                let mut stdout = std::io::stdout();
                let _ = crossterm::execute!(stdout, SetForegroundColor(Color::Green));
                print!("  ✓ ");
                let _ = crossterm::execute!(
                    stdout,
                    SetForegroundColor(Color::White),
                    SetAttribute(Attribute::Bold)
                );
                print!("{:20}", profile.alias);
                let _ = crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));
                let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
                print!("{} ", account.address());
                let _ = crossterm::execute!(stdout, SetForegroundColor(Color::Yellow));
                println!("({net})");
                let _ = crossterm::execute!(stdout, ResetColor);
                imported += 1;
            }
            Err(e) => {
                output::print_warning(&format!("Failed to import '{}': {e:#}", profile.alias));
            }
        }
    }

    println!();
    if imported > 0 {
        output::print_success(&format!(
            "Imported {imported} profile(s){skipped_msg}",
            skipped_msg = if skipped > 0 {
                format!(", skipped {skipped} (already exist)")
            } else {
                String::new()
            }
        ));
    } else if skipped > 0 {
        output::print_dim(&format!("All {skipped} profiles already exist in vault."));
    }

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
        // Persist to config
        session.config.network = Some(net.to_string());
        session.config.save()?;
        output::print_success(&format!("Switched to {net} (saved to config)"));
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
// Config commands
// ---------------------------------------------------------------------------

fn handle_config(args: &[String], session: &mut Session) -> Result<()> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("list");

    match sub {
        "list" | "ls" => {
            let mut stdout = std::io::stdout();
            output::print_header("Configuration");
            let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
            println!(
                "    {}",
                CliConfig::default_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "unknown".to_string())
            );
            let _ = crossterm::execute!(stdout, ResetColor);
            println!();

            for (key, desc) in CliConfig::known_keys() {
                let value = session.config.get(key);
                print!("    ");
                let _ = crossterm::execute!(
                    stdout,
                    SetForegroundColor(Color::Cyan),
                    SetAttribute(Attribute::Bold)
                );
                print!("{key:20}");
                let _ = crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));

                match value {
                    Some(v) => {
                        let _ = crossterm::execute!(
                            stdout,
                            SetForegroundColor(Color::White),
                            SetAttribute(Attribute::Bold)
                        );
                        print!("{v}");
                        let _ =
                            crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));
                    }
                    None => {
                        let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
                        print!("(unset)");
                        let _ = crossterm::execute!(stdout, ResetColor);
                    }
                }

                let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
                println!("  — {desc}");
                let _ = crossterm::execute!(stdout, ResetColor);
            }
            println!();
        }
        "get" => {
            let key = args.get(1).context("usage: config get <key>")?;
            match session.config.get(key) {
                Some(v) => output::print_kv(key, &v),
                None => output::print_dim(&format!("{key} is not set")),
            }
        }
        "set" => {
            let key = args.get(1).context("usage: config set <key> <value>")?;
            let value = args.get(2).context("usage: config set <key> <value>")?;
            session.config.set(key, value)?;
            session.config.save()?;

            // Apply certain changes to the live session
            match key.as_str() {
                "network" | "node-url" | "node_url" | "api-key" | "api_key" | "json-output"
                | "json_output" => {
                    apply_config_defaults(&mut session.global, &session.config);
                }
                "default_account" | "default-account" => {
                    // Also activate if vault is unlocked
                    if let Some(ref vault) = session.vault
                        && vault.get(value).is_some()
                    {
                        session.active_account = Some(value.to_string());
                        output::print_info(&format!("Active account set to '{value}'"));
                    }
                }
                _ => {}
            }

            output::print_success(&format!("Set {key} = {value}"));
        }
        "unset" | "rm" | "remove" => {
            let key = args.get(1).context("usage: config unset <key>")?;
            session.config.unset(key)?;
            session.config.save()?;
            output::print_success(&format!("Unset {key}"));
        }
        "path" => {
            let path = CliConfig::default_path()?;
            output::print_kv("Config file", &path.display().to_string());
        }
        _ => {
            print_config_help();
        }
    }
    Ok(())
}

fn print_config_help() {
    let mut stdout = std::io::stdout();

    output::print_header("Config Commands");

    let commands = [
        ("list", "Show all config values"),
        ("get <key>", "Get a specific value"),
        ("set <key> <value>", "Set a config value (persisted)"),
        ("unset <key>", "Remove a config value"),
        ("path", "Show config file path"),
    ];

    for (cmd, desc) in &commands {
        print!("    ");
        let _ = crossterm::execute!(
            stdout,
            SetForegroundColor(Color::Cyan),
            SetAttribute(Attribute::Bold)
        );
        print!("config {cmd:22}");
        let _ = crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));
        let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
        println!("{desc}");
        let _ = crossterm::execute!(stdout, ResetColor);
    }

    println!();
    output::print_dim("Available keys:");
    for (key, desc) in CliConfig::known_keys() {
        let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
        println!("      {key:20}{desc}");
        let _ = crossterm::execute!(stdout, ResetColor);
    }
    println!();
}

// ---------------------------------------------------------------------------
// SDK command passthrough
// ---------------------------------------------------------------------------

/// Handle SDK commands. If a command needs `--private-key`, and none is supplied
/// but an active account is set, we inject the stored credential. If a command
/// needs `--address` or `--sender`, we auto-inject from the active account.
async fn handle_sdk_command(cmd: &str, args: &[String], session: &mut Session) -> Result<()> {
    // Build a clap-style argument vector: ["aptos-repl", <cmd>, ...args]
    let mut argv: Vec<String> = vec!["aptos-repl".to_string(), cmd.to_string()];
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

    // Auto-inject --address from active account for read-only commands
    let needs_address = argv.iter().any(|a| {
        a == "balance"
            || a == "lookup"
            || a == "resources"
            || a == "resource"
            || a == "modules"
            || a == "fund"
            || a == "inspect"
    });
    let has_address = argv.iter().any(|a| a == "--address");
    if needs_address
        && !has_address
        && let Some(ref alias) = session.active_account
        && let Some(vault) = &session.vault
        && let Some(cred) = vault.get(alias)
    {
        let account = cred.to_cli_account()?;
        argv.push("--address".to_string());
        argv.push(account.address().to_string());
    }

    // Auto-inject --sender from active account for simulate
    let needs_sender = argv.iter().any(|a| a == "simulate");
    let has_sender = argv.iter().any(|a| a == "--sender");
    if needs_sender
        && !has_sender
        && let Some(ref alias) = session.active_account
        && let Some(vault) = &session.vault
        && let Some(cred) = vault.get(alias)
    {
        let account = cred.to_cli_account()?;
        argv.push("--sender".to_string());
        argv.push(account.address().to_string());
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

    // Parse and dispatch (argv stays in-process, never passed to an external process)
    let result = dispatch_command(&argv).await;

    // Zeroize any sensitive data in the argument vector (private keys, API keys)
    for arg in &mut argv {
        arg.zeroize();
    }

    result
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
        Some(crate::Command::Account(cmd)) => cmd.run(&cli.global).await,
        Some(crate::Command::Key(cmd)) => cmd.run(&cli.global),
        Some(crate::Command::Move(cmd)) => cmd.run(&cli.global).await,
        Some(crate::Command::Transaction(cmd)) => cmd.run(&cli.global).await,
        Some(crate::Command::Info(cmd)) => cmd.run(&cli.global).await,
        Some(crate::Command::Repl) | None => {
            output::print_dim("Already in REPL mode.");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

/// Returns `true` if the input line contains credential material that must
/// never be persisted to the REPL history file.
pub(crate) fn contains_secret(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();

    // Check for common secret flags
    if lower.contains("--private-key")
        || lower.contains("--private_key")
        || lower.contains("--secret")
        || lower.contains("--mnemonic")
        || lower.contains("--seed")
        || lower.contains("password")
    {
        return true;
    }

    // Check for credential add command (user pastes a private key)
    if lower.starts_with("cred") && lower.contains("add") {
        return true;
    }

    // Check for long hex strings that look like private keys (>= 64 hex chars)
    for token in line.split_whitespace() {
        let stripped = token.strip_prefix("0x").unwrap_or(token);
        if stripped.len() >= 64 && stripped.chars().all(|c| c.is_ascii_hexdigit()) {
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Password validation
// ---------------------------------------------------------------------------

/// Validate password strength. Requires:
/// - At least 12 characters
/// - At least one letter and one non-letter (digit, symbol, etc.)
pub(crate) fn validate_password_strength(password: &str) -> Result<()> {
    if password.len() < 12 {
        bail!(
            "Password must be at least 12 characters (got {}).",
            password.len()
        );
    }
    let has_letter = password.chars().any(|c| c.is_ascii_alphabetic());
    let has_non_letter = password.chars().any(|c| !c.is_ascii_alphabetic());
    if !has_letter || !has_non_letter {
        bail!("Password must contain both letters and numbers/symbols.");
    }
    Ok(())
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
    print_help_row(&mut stdout, "network <name>", "Switch network (saved)");
    print_help_row(
        &mut stdout,
        "config <sub>",
        "Persistent settings (get/set/list)",
    );

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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // contains_secret
    // -----------------------------------------------------------------------

    #[test]
    fn contains_secret_private_key_flag() {
        assert!(contains_secret("account transfer --private-key abc123"));
    }

    #[test]
    fn contains_secret_private_key_underscore() {
        assert!(contains_secret("move run --private_key abc123"));
    }

    #[test]
    fn contains_secret_mnemonic() {
        assert!(contains_secret("key from-mnemonic --mnemonic word1 word2"));
    }

    #[test]
    fn contains_secret_seed() {
        assert!(contains_secret("import --seed myseed"));
    }

    #[test]
    fn contains_secret_case_insensitive() {
        assert!(contains_secret("--PRIVATE-KEY abc"));
        assert!(contains_secret("--Private_Key abc"));
        assert!(contains_secret("--MNEMONIC words"));
    }

    #[test]
    fn contains_secret_normal_command_is_safe() {
        assert!(!contains_secret("account balance --address 0x1"));
        assert!(!contains_secret("info ledger"));
        assert!(!contains_secret("network testnet"));
        assert!(!contains_secret("whoami"));
    }

    #[test]
    fn contains_secret_empty_string() {
        assert!(!contains_secret(""));
    }

    #[test]
    fn contains_secret_secret_flag() {
        assert!(contains_secret("some-command --secret value"));
    }

    // -----------------------------------------------------------------------
    // parse_network_str
    // -----------------------------------------------------------------------

    #[test]
    fn parse_network_str_mainnet() {
        let net = parse_network_str("mainnet").unwrap();
        assert!(matches!(net, NetworkArg::Mainnet));
    }

    #[test]
    fn parse_network_str_testnet() {
        let net = parse_network_str("testnet").unwrap();
        assert!(matches!(net, NetworkArg::Testnet));
    }

    #[test]
    fn parse_network_str_devnet() {
        let net = parse_network_str("devnet").unwrap();
        assert!(matches!(net, NetworkArg::Devnet));
    }

    #[test]
    fn parse_network_str_local() {
        let net = parse_network_str("local").unwrap();
        assert!(matches!(net, NetworkArg::Local));
    }

    #[test]
    fn parse_network_str_unknown_returns_none() {
        assert!(parse_network_str("foonet").is_none());
        assert!(parse_network_str("").is_none());
        assert!(parse_network_str("MAINNET").is_none()); // case-sensitive
    }

    // -----------------------------------------------------------------------
    // contains_secret — enhanced patterns
    // -----------------------------------------------------------------------

    #[test]
    fn contains_secret_long_hex_string() {
        // 64 hex chars looks like a private key
        let hex = "a".repeat(64);
        assert!(contains_secret(&format!("something {hex}")));
    }

    #[test]
    fn contains_secret_long_hex_with_0x_prefix() {
        let hex = "b".repeat(64);
        assert!(contains_secret(&format!("something 0x{hex}")));
    }

    #[test]
    fn contains_secret_short_hex_is_safe() {
        // Short hex (like addresses) should be fine
        assert!(!contains_secret("account balance --address 0x1234abcd"));
    }

    #[test]
    fn contains_secret_credential_add() {
        assert!(contains_secret("credential add my-key ed25519"));
        assert!(contains_secret("cred add alice"));
    }

    #[test]
    fn contains_secret_password_keyword() {
        assert!(contains_secret("change-password"));
        assert!(contains_secret("Password reset"));
    }

    // -----------------------------------------------------------------------
    // validate_password_strength
    // -----------------------------------------------------------------------

    #[test]
    fn password_too_short() {
        assert!(validate_password_strength("short1!").is_err());
    }

    #[test]
    fn password_no_numbers() {
        assert!(validate_password_strength("onlylettershere").is_err());
    }

    #[test]
    fn password_no_letters() {
        assert!(validate_password_strength("123456789012").is_err());
    }

    #[test]
    fn password_valid() {
        assert!(validate_password_strength("MyPassword123!").is_ok());
    }

    #[test]
    fn password_valid_with_symbols() {
        assert!(validate_password_strength("p@ssw0rd!#$%^").is_ok());
    }
}

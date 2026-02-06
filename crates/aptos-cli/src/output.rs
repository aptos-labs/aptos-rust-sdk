//! Colorized output formatting for CLI results.
//!
//! Uses ANSI escape codes via crossterm for colored terminal output.
//! All functions gracefully degrade to plain text if the terminal does
//! not support colors.

use anyhow::Result;
use crossterm::style::{Attribute, Color, ResetColor, SetAttribute, SetForegroundColor, Stylize};

/// Print a value as JSON (pretty-printed) with syntax highlighting.
pub fn print_json(value: &serde_json::Value) -> Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    for line in json.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('"') && trimmed.contains(':') {
            // Key-value line: color the key
            if let Some(colon_pos) = line.find(':') {
                let key_part = &line[..colon_pos + 1];
                let val_part = &line[colon_pos + 1..];
                print!("{}", key_part.cyan());
                println!("{val_part}");
            } else {
                println!("{line}");
            }
        } else {
            println!("{line}");
        }
    }
    Ok(())
}

/// Print a key-value pair in human-readable format.
pub fn print_kv(key: &str, value: &str) {
    let mut stdout = std::io::stdout();
    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
    print!("  {key}: ");
    let _ = crossterm::execute!(stdout, ResetColor);
    println!("{value}");
}

/// Print a section header.
pub fn print_header(title: &str) {
    let mut stdout = std::io::stdout();
    println!();
    let _ = crossterm::execute!(
        stdout,
        SetForegroundColor(Color::Cyan),
        SetAttribute(Attribute::Bold)
    );
    print!("--- {title} ---");
    let _ = crossterm::execute!(stdout, ResetColor, SetAttribute(Attribute::Reset));
    println!();
}

/// Print a success message.
pub fn print_success(msg: &str) {
    let mut stdout = std::io::stdout();
    let _ = crossterm::execute!(
        stdout,
        SetForegroundColor(Color::Green),
        SetAttribute(Attribute::Bold)
    );
    print!("  ✓ ");
    let _ = crossterm::execute!(stdout, SetAttribute(Attribute::Reset));
    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::Green));
    print!("{msg}");
    let _ = crossterm::execute!(stdout, ResetColor);
    println!();
}

/// Print a warning message.
pub fn print_warning(msg: &str) {
    let mut stderr = std::io::stderr();
    let _ = crossterm::execute!(
        stderr,
        SetForegroundColor(Color::Yellow),
        SetAttribute(Attribute::Bold)
    );
    eprint!("  ⚠ ");
    let _ = crossterm::execute!(stderr, SetAttribute(Attribute::Reset));
    let _ = crossterm::execute!(stderr, SetForegroundColor(Color::Yellow));
    eprint!("{msg}");
    let _ = crossterm::execute!(stderr, ResetColor);
    eprintln!();
}

/// Print an error message.
pub fn print_error(msg: &str) {
    let mut stderr = std::io::stderr();
    let _ = crossterm::execute!(
        stderr,
        SetForegroundColor(Color::Red),
        SetAttribute(Attribute::Bold)
    );
    eprint!("  ✗ ");
    let _ = crossterm::execute!(stderr, SetAttribute(Attribute::Reset));
    let _ = crossterm::execute!(stderr, SetForegroundColor(Color::Red));
    eprint!("{msg}");
    let _ = crossterm::execute!(stderr, ResetColor);
    eprintln!();
}

/// Print an informational message.
pub fn print_info(msg: &str) {
    let mut stdout = std::io::stdout();
    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::Blue));
    print!("  ℹ {msg}");
    let _ = crossterm::execute!(stdout, ResetColor);
    println!();
}

/// Print a dimmed/hint message.
pub fn print_dim(msg: &str) {
    let mut stdout = std::io::stdout();
    let _ = crossterm::execute!(stdout, SetForegroundColor(Color::DarkGrey));
    print!("  {msg}");
    let _ = crossterm::execute!(stdout, ResetColor);
    println!();
}

/// Helper to format octas as APT with both units shown.
pub fn format_apt(octas: u64) -> String {
    let apt = octas as f64 / 100_000_000.0;
    format!("{apt:.8} APT ({octas} octas)")
}

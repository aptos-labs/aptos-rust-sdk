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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_apt_zero() {
        let s = format_apt(0);
        assert_eq!(s, "0.00000000 APT (0 octas)");
    }

    #[test]
    fn format_apt_one_apt() {
        let s = format_apt(100_000_000);
        assert_eq!(s, "1.00000000 APT (100000000 octas)");
    }

    #[test]
    fn format_apt_fractional() {
        let s = format_apt(123_456_789);
        assert_eq!(s, "1.23456789 APT (123456789 octas)");
    }

    #[test]
    fn format_apt_small_amount() {
        let s = format_apt(1);
        assert_eq!(s, "0.00000001 APT (1 octas)");
    }

    #[test]
    fn format_apt_large_amount() {
        // 1 billion APT
        let s = format_apt(100_000_000_000_000_000);
        assert!(s.contains("APT"));
        assert!(s.contains("octas"));
    }

    #[test]
    fn print_json_valid() {
        let val = serde_json::json!({"key": "value"});
        assert!(print_json(&val).is_ok());
    }

    #[test]
    fn print_json_array() {
        let val = serde_json::json!([1, 2, 3]);
        assert!(print_json(&val).is_ok());
    }

    #[test]
    fn print_json_null() {
        let val = serde_json::json!(null);
        assert!(print_json(&val).is_ok());
    }
}

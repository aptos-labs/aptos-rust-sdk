//! Output formatting for CLI results.

use anyhow::Result;

/// Print a value as JSON (pretty-printed).
pub fn print_json(value: &serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

/// Print a key-value pair in human-readable format.
pub fn print_kv(key: &str, value: &str) {
    println!("  {key}: {value}");
}

/// Print a section header.
pub fn print_header(title: &str) {
    println!("\n--- {title} ---");
}

/// Print a success message.
pub fn print_success(msg: &str) {
    println!("Success: {msg}");
}

/// Print a warning message.
pub fn print_warning(msg: &str) {
    eprintln!("Warning: {msg}");
}

/// Helper to format octas as APT with both units shown.
pub fn format_apt(octas: u64) -> String {
    let apt = octas as f64 / 100_000_000.0;
    format!("{apt:.8} APT ({octas} octas)")
}

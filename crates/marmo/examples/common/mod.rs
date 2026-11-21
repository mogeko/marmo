//! Shared helpers for the Cargo examples.
#![allow(dead_code)]

use std::error::Error;
use std::fmt::Write as _;

/// Returns the positional argument at `index` (1 is the first after the
/// program name).
pub fn arg(index: usize) -> Option<String> {
    std::env::args().nth(index)
}

/// Returns a required positional argument.
pub fn required(index: usize, name: &str) -> Result<String, Box<dyn Error>> {
    arg(index).ok_or_else(|| format!("missing {name}").into())
}

/// Reads a PEM or DER credential from disk.
pub fn read(path: &str) -> Result<String, Box<dyn Error>> {
    Ok(std::fs::read_to_string(path)?)
}

/// Returns true for a loopback server endpoint (`127.0.0.0/8`, `::1`, or
/// `localhost`).
pub fn is_loopback(server: &str) -> bool {
    marmo::Endpoint::parse(server).is_ok_and(|endpoint| {
        endpoint.ip().is_some_and(|ip| ip.is_loopback()) || endpoint.domain() == Some("localhost")
    })
}

/// Escapes a string for embedding in a JSON document.
pub fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            control if control < ' ' => {
                let _ = write!(escaped, "\\u{:04x}", u32::from(control));
            }
            other => escaped.push(other),
        }
    }
    escaped.push('"');
    escaped
}

/// Builds, binds, and serves one instance until the process is stopped.
pub async fn serve(json: String) -> Result<(), Box<dyn Error>> {
    let config = marmo::Config::from_json(&json)?;
    let instance = marmo::Instance::builder(config).build()?;
    let bound = instance.bind().await?;
    for address in bound.local_addrs() {
        println!("{} {:?} {}", address.tag, address.network, address.addr);
    }
    bound.serve().await?;
    Ok(())
}

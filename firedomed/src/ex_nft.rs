use std::process::Command;

pub fn initialize() -> Result<(), String> {
    delete_firewall();
    create_table()?;
    create_input_chain()?;
    create_output_chain()?;
    create_forward_chain()?;
    Ok(())
}

// Blocks an IP on the specified chain ("input" or "output")
pub fn block_ip(direction: &str, ip: &str) -> Result<(), String> {
    let field = if direction == "input" {
        "saddr"
    } else {
        "daddr"
    };
    run_nft(&[
        "add", "rule", "inet", "firedome", direction, "ip", field, ip, "drop",
    ])
}

// Allows an IP on the specified chain ("input" or "output")
pub fn allow_ip(direction: &str, ip: &str) -> Result<(), String> {
    let field = if direction == "input" {
        "saddr"
    } else {
        "daddr"
    };
    run_nft(&[
        "add", "rule", "inet", "firedome", direction, "ip", field, ip, "accept",
    ])
}

// Blocks a port on the specified chain ("input" or "output")
pub fn block_port(direction: &str, port: &str) -> Result<(), String> {
    let field = if direction == "input" {
        "dport"
    } else {
        "dport"
    };
    run_nft(&[
        "add", "rule", "inet", "firedome", direction, "tcp", field, port, "drop",
    ])?;
    run_nft(&[
        "add", "rule", "inet", "firedome", direction, "udp", field, port, "drop",
    ])
}

// Allows a port on the specified chain ("input" or "output")
pub fn allow_port(direction: &str, port: &str) -> Result<(), String> {
    let field = if direction == "input" {
        "dport"
    } else {
        "dport"
    };
    run_nft(&[
        "add", "rule", "inet", "firedome", direction, "tcp", field, port, "accept",
    ])?;
    run_nft(&[
        "add", "rule", "inet", "firedome", "output", "udp", field, port, "accept",
    ])
}

fn delete_firewall() {
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "firedome"])
        .output();
}

fn create_table() -> Result<(), String> {
    run_nft(&["add", "table", "inet", "firedome"])
}

// Default policy for INPUT chain is set to "drop" (Blocks all incoming traffic by default)
fn create_input_chain() -> Result<(), String> {
    run_nft(&[
        "add", "chain", "inet", "firedome", "input", "{", "type", "filter", "hook", "input",
        "priority", "0", ";", "policy", "drop", ";", "}",
    ])
}

// Default policy for OUTPUT chain remains "accept"
fn create_output_chain() -> Result<(), String> {
    run_nft(&[
        "add", "chain", "inet", "firedome", "output", "{", "type", "filter", "hook", "output",
        "priority", "0", ";", "policy", "accept", ";", "}",
    ])
}

fn create_forward_chain() -> Result<(), String> {
    run_nft(&[
        "add", "chain", "inet", "firedome", "forward", "{", "type", "filter", "hook", "forward",
        "priority", "0", ";", "policy", "accept", ";", "}",
    ])
}

fn run_nft(args: &[&str]) -> Result<(), String> {
    let output = Command::new("nft")
        .args(args)
        .output()
        .map_err(|error| format!("Failed to execute nft: {}", error))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

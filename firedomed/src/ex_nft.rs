use std::process::Command;

pub fn initialize() -> Result<(), String> {
    delete_firewall();
    create_table()?;
    create_input_chain()?;
    create_output_chain()?;
    create_forward_chain()?;
    Ok(())
}

pub fn block_ip(ip: &str) -> Result<(), String> {
    run_nft(&[
        "add", "rule", "inet", "firedome", "output", "ip", "daddr", ip, "drop",
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

fn create_input_chain() -> Result<(), String> {
    run_nft(&[
        "add", "chain", "inet", "firedome", "input", "{", "type", "filter", "hook", "input",
        "priority", "0", ";", "policy", "accept", ";", "}",
    ])
}

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

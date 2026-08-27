use std::process::Command;

pub fn initialize() -> Result<(), String> {
    delete_firewall();
    create_table()?;
    create_input_chain()?;
    create_output_chain()?; // Creates default-drop chain
    create_forward_chain()?;
    Ok(())
}

// 1. ALLOW IP: Adds a rule to explicitly ALLOW traffic to this target IP
pub fn allow_ip(ip: &str) -> Result<(), String> {
    run_nft(&[
        "add", "rule", "inet", "firedome", "output", "ip", "daddr", ip, "accept",
    ])
}

// 2. BLOCK IP: Removes the explicit accept rule for this IP (reverting it to default DROP)
pub fn block_ip(ip: &str) -> Result<(), String> {
    let handles = get_rule_handles(ip)?;
    if handles.is_empty() {
        return Ok(()); // Already blocked by default chain policy
    }

    for handle in handles {
        run_nft(&[
            "delete", "rule", "inet", "firedome", "output", "handle", &handle,
        ])?;
    }
    Ok(())
}

// 3. ALLOW PORT: Adds explicit rule to allow TCP/UDP traffic on a port
pub fn allow_port(port: &str) -> Result<(), String> {
    run_nft(&[
        "add", "rule", "inet", "firedome", "output", "tcp", "dport", port, "accept",
    ])?;
    run_nft(&[
        "add", "rule", "inet", "firedome", "output", "udp", "dport", port, "accept",
    ])
}

// 4. BLOCK PORT: Removes the explicit accept rules for this port
pub fn block_port(port: &str) -> Result<(), String> {
    let handles = get_rule_handles(port)?;
    if handles.is_empty() {
        return Ok(());
    }

    for handle in handles {
        run_nft(&[
            "delete", "rule", "inet", "firedome", "output", "handle", &handle,
        ])?;
    }
    Ok(())
}

// Helper: Get rule handles matching a given target (IP or Port)
fn get_rule_handles(target: &str) -> Result<Vec<String>, String> {
    let output = Command::new("nft")
        .args(["-a", "list", "chain", "inet", "firedome", "output"])
        .output()
        .map_err(|e| format!("Failed to execute nft: {}", e))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut handles = Vec::new();

    for line in stdout.lines() {
        if line.contains(target) {
            if let Some(handle_str) = line.split("# handle ").nth(1) {
                if let Some(handle) = handle_str.split_whitespace().next() {
                    handles.push(handle.to_string());
                }
            }
        }
    }

    Ok(handles)
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

// CHANGED: Default policy is now "drop" instead of "accept"
fn create_output_chain() -> Result<(), String> {
    run_nft(&[
        "add", "chain", "inet", "firedome", "output", "{", "type", "filter", "hook", "output",
        "priority", "0", ";", "policy", "drop", ";", "}",
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

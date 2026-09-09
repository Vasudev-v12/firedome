use std::process::Command;

const TABLE: &str = "firedome";

// nft command execution function
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

pub fn initialize(
    input_policy: &str,
    output_policy: &str,
    forward_policy: &str,
) -> Result<(), String> {
    delete_firewall();
    create_inet_table()?;
    create_ingress_chain()?;
    create_prerouting_chain()?;
    create_input_chain(input_policy)?;
    create_forward_chain(forward_policy)?;
    create_output_chain(output_policy)?;
    create_postrouting_chain()?;
    Ok(())
}

fn delete_firewall() {
    // delete inet table
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", TABLE])
        .output();
}

fn create_inet_table() -> Result<(), String> {
    run_nft(&["add", "table", "inet", TABLE])
}

fn create_ingress_chain() -> Result<(), String> {
    run_nft(&[
        "add", "chain", "inet", TABLE, "ingress", "{", "type", "filter", "hook", "ingress",
        "priority", "0", ";", "policy", "accept", ";", "}",
    ])
}

fn create_prerouting_chain() -> Result<(), String> {
    run_nft(&[
        "add",
        "chain",
        "inet",
        TABLE,
        "prerouting",
        "{",
        "type",
        "filter",
        "hook",
        "prerouting",
        "priority",
        "0",
        ";",
        "policy",
        "accept",
        ";",
        "}",
    ])
}

fn create_input_chain(policy: &str) -> Result<(), String> {
    let policy = validate_policy(policy)?;

    run_nft(&[
        "add", "chain", "inet", TABLE, "input", "{", "type", "filter", "hook", "input", "priority",
        "0", ";", "policy", policy, ";", "}",
    ])
}

fn create_forward_chain(policy: &str) -> Result<(), String> {
    let policy = validate_policy(policy)?;

    run_nft(&[
        "add", "chain", "inet", TABLE, "forward", "{", "type", "filter", "hook", "forward",
        "priority", "0", ";", "policy", policy, ";", "}",
    ])
}

fn create_output_chain(policy: &str) -> Result<(), String> {
    let policy = validate_policy(policy)?;

    run_nft(&[
        "add", "chain", "inet", TABLE, "output", "{", "type", "filter", "hook", "output",
        "priority", "0", ";", "policy", policy, ";", "}",
    ])
}

fn create_postrouting_chain() -> Result<(), String> {
    run_nft(&[
        "add",
        "chain",
        "inet",
        TABLE,
        "postrouting",
        "{",
        "type",
        "filter",
        "hook",
        "postrouting",
        "priority",
        "0",
        ";",
        "policy",
        "accept",
        ";",
        "}",
    ])
}

fn validate_policy(policy: &str) -> Result<&str, String> {
    match policy.to_uppercase().as_str() {
        "ACCEPT" => Ok("accept"),

        "DROP" => Ok("drop"),

        _ => Err(format!(
            "Invalid firewall policy '{}'. Use ACCEPT or DROP.",
            policy
        )),
    }
}

pub fn block_ip(direction: &str, ip: &str) -> Result<(), String> {
    let direction = direction.to_lowercase();

    let field = match direction.as_str() {
        "input" => "saddr",

        "output" => "daddr",

        _ => {
            return Err("IP rules currently support INPUT or OUTPUT only.".to_string());
        }
    };

    run_nft(&[
        "add", "rule", "inet", TABLE, &direction, "ip", field, ip, "drop",
    ])
}

pub fn allow_ip(direction: &str, ip: &str) -> Result<(), String> {
    let direction = direction.to_lowercase();

    let field = match direction.as_str() {
        "input" => "saddr",

        "output" => "daddr",

        _ => {
            return Err("IP rules currently support INPUT or OUTPUT only.".to_string());
        }
    };

    run_nft(&[
        "add", "rule", "inet", TABLE, &direction, "ip", field, ip, "accept",
    ])
}

pub fn block_port(direction: &str, port: &str) -> Result<(), String> {
    let direction = direction.to_lowercase();

    match direction.as_str() {
        "input" | "output" => {}

        _ => {
            return Err("Port rules currently support INPUT or OUTPUT only.".to_string());
        }
    }

    // TCP
    run_nft(&[
        "add", "rule", "inet", TABLE, &direction, "tcp", "dport", port, "drop",
    ])?;

    // UDP
    run_nft(&[
        "add", "rule", "inet", TABLE, &direction, "udp", "dport", port, "drop",
    ])
}

pub fn allow_port(direction: &str, port: &str) -> Result<(), String> {
    let direction = direction.to_lowercase();

    match direction.as_str() {
        "input" | "output" => {}

        _ => {
            return Err("Port rules currently support INPUT or OUTPUT only.".to_string());
        }
    }

    // TCP
    run_nft(&[
        "add", "rule", "inet", TABLE, &direction, "tcp", "dport", port, "accept",
    ])?;

    // UDP
    run_nft(&[
        "add", "rule", "inet", TABLE, &direction, "udp", "dport", port, "accept",
    ])
}

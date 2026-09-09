mod ex_nft;
use std::fs;

fn main() {
    println!("Firewall starting ...");
    let rules = match fs::read_to_string("/etc/firedome/rules.conf") {
        Ok(content) => content,

        Err(error) => {
            eprintln!("Failed to read rules.conf: {}", error);
            std::process::exit(1);
        }
    };

    // Default policies
    let mut input_policy = "ACCEPT";
    let mut output_policy = "ACCEPT";
    let mut forward_policy = "ACCEPT";

    for line in rules.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 3 {
            continue;
        }
        if parts[0].eq_ignore_ascii_case("POLICY") {
            let direction = parts[1].to_uppercase();
            let policy = parts[2].to_uppercase();

            match direction.as_str() {
                "INPUT" => {
                    input_policy = match policy.as_str() {
                        "DROP" => "DROP",
                        "ACCEPT" => "ACCEPT",
                        _ => {
                            eprintln!("Invalid INPUT policy: {}", parts[2]);
                            continue;
                        }
                    };
                }

                "OUTPUT" => {
                    output_policy = match policy.as_str() {
                        "DROP" => "DROP",
                        "ACCEPT" => "ACCEPT",
                        _ => {
                            eprintln!("Invalid OUTPUT policy: {}", parts[2]);
                            continue;
                        }
                    };
                }

                "FORWARD" => {
                    forward_policy = match policy.as_str() {
                        "DROP" => "DROP",
                        "ACCEPT" => "ACCEPT",
                        _ => {
                            eprintln!("Invalid FORWARD policy: {}", parts[2]);
                            continue;
                        }
                    };
                }
                _ => {
                    eprintln!("Unknown policy direction: {}", parts[1]);
                }
            }
        }
    }

    if let Err(error) = ex_nft::initialize(input_policy, output_policy, forward_policy) {
        eprintln!("Failed to initialize nftables:");
        eprintln!("{}", error);
        std::process::exit(1);
    }

    println!("nftables initialized.");

    // apply rules in rules.conf
    for line in rules.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 3 {
            eprintln!("Invalid rule: {}", line);
            continue;
        }

        let action = parts[0].to_uppercase();
        let direction = parts[1].to_uppercase();
        let value = parts[2];

        match action.as_str() {
            "BLOCK" => {
                println!("Blocking {} {}", direction, value);

                if let Err(error) = ex_nft::block_ip(&direction, value) {
                    eprintln!("Failed to block {}: {}", value, error);
                }
            }
            "ALLOW" => {
                println!("Allowing {} {}", direction, value);

                if let Err(error) = ex_nft::allow_ip(&direction, value) {
                    eprintln!("Failed to allow {}: {}", value, error);
                }
            }
            "BLOCK_PORT" => {
                println!("Blocking port {} {}", direction, value);

                if let Err(error) = ex_nft::block_port(&direction, value) {
                    eprintln!("Failed to block port {}: {}", value, error);
                }
            }
            "ALLOW_PORT" => {
                println!("Allowing port {} {}", direction, value);

                if let Err(error) = ex_nft::allow_port(&direction, value) {
                    eprintln!("Failed to allow port {}: {}", value, error);
                }
            }
            "POLICY" => {}
            _ => {
                eprintln!("Unknown action: {}", action);
            }
        }
    }

    println!("Firewall active.");

    loop {
        std::thread::park();
    }
}

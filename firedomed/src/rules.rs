use std::fs;

use crate::models::{Action, Rule, Target};

pub fn check_ip(ip: &str, rules: &[Rule]) -> bool {

    for rule in rules {

        match (&rule.action, &rule.target) {

            (Action::Block, Target::Ip(rule_ip))
                if rule_ip == ip =>
            {
                return false;
            }

            (Action::Allow, Target::Ip(rule_ip))
                if rule_ip == ip =>
            {
                return true;
            }

            _ => {}

        }

    }

    true

}

pub fn load_rules(path: &str) -> Vec<Rule> {

    let mut rules = Vec::new();

    let content = fs::read_to_string(path)
        .expect("Unable to read rules.conf");

    for line in content.lines() {

        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() != 2 {
            println!("Invalid rule: {}", line);
            continue;
        }

        match parts[0] {

            "ALLOW" => {

                rules.push(
                    Rule {
                        action: Action::Allow,
                        target: Target::Ip(parts[1].to_string()),
                    }
                );

            }

            "BLOCK" => {

                rules.push(
                    Rule {
                        action: Action::Block,
                        target: Target::Ip(parts[1].to_string()),
                    }
                );

            }

            "ALLOW_PORT" => {

                let port = parts[1].parse::<u16>().unwrap();

                rules.push(
                    Rule {
                        action: Action::AllowPort,
                        target: Target::Port(port),
                    }
                );

            }

            "BLOCK_PORT" => {

                let port = parts[1].parse::<u16>().unwrap();

                rules.push(
                    Rule {
                        action: Action::BlockPort,
                        target: Target::Port(port),
                    }
                );

            }

            _ => println!("Unknown rule: {}", line)

        }

    }

    rules

}
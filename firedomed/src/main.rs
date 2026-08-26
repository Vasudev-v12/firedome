// mod config;
mod ex_nft;
// mod firewall;
// mod logger;
// mod models;
// mod rules;

//use crate::models::{Packet, Protocol};
use std::fs;

// use std::{
//     fs::{self, OpenOptions},
//     io::Write,
//     thread,
//     time::Duration,
// };

// use chrono::Local;

// fn log(message: &str) {
//     fs::create_dir_all("../logs").unwrap();

//     let mut file = OpenOptions::new()
//         .append(true)
//         .create(true)
//         .open("../logs/firewall.log")
//         .unwrap();

//     let timestamp = Local::now();

//     writeln!(
//         file,
//         "[{}] {}",
//         timestamp.format("%Y-%m-%d %H:%M:%S"),
//         message
//     )
//     .unwrap();
// }

// fn load_file(path: &str) -> Vec<String> {
//     let content = fs::read_to_string(path).expect("Unable to read file");

//     content
//         .lines()
//         .filter(|line| !line.trim().is_empty())
//         .map(|line| line.to_string())
//         .collect()
// }

fn main() {
    println!("Firewall starting ...");
    if let Err(error) = ex_nft::initialize() {
        eprintln!("Failed to initialize nftables:");
        eprintln!("{}", error);
        std::process::exit(1);
    }

    println!("nftables initialized.");
    let rules = match fs::read_to_string("/etc/firedome/rules.conf") {
        Ok(content) => content,
        Err(error) => {
            eprintln!("Failed to read rules.conf: {}", error);
            std::process::exit(1);
        }
    };
    for line in rules.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 2 {
            eprintln!("Invalid rule: {}", line);
            continue;
        }
        if parts[0] == "BLOCK" {
            let ip = parts[1];
            println!("Blocking {}", ip);
            if let Err(error) = ex_nft::block_ip(ip) {
                eprintln!("Failed to block {}: {}", ip, error);
            }
        }
    }
    println!("Firewall started.");

    loop {
        std::thread::park();
    }
}

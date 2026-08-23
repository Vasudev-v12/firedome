mod config;
mod ex_nft;
mod firewall;
mod logger;
mod models;
mod rules;

use crate::models::{Packet, Protocol};

use std::{
    fs::{self, OpenOptions},
    io::Write,
    thread,
    time::Duration,
};

use chrono::Local;

fn log(message: &str) {
    fs::create_dir_all("../logs").unwrap();

    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("../logs/firewall.log")
        .unwrap();

    let timestamp = Local::now();

    writeln!(
        file,
        "[{}] {}",
        timestamp.format("%Y-%m-%d %H:%M:%S"),
        message
    )
    .unwrap();
}

fn load_file(path: &str) -> Vec<String> {
    let content = fs::read_to_string(path).expect("Unable to read file");

    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.to_string())
        .collect()
}

fn main() {
    println!("==============================");
    println!("     Firedom Version 0.1");
    println!("==============================");

    log("Firewall starting");

    println!("Loading configuration...");

    let config = load_file("../config/firewall.conf");

    for line in &config {
        println!("CONFIG: {}", line);
    }

    println!();
    println!("Loading firewall rules...");

    let rules = rules::load_rules("../config/rules.conf");

    println!();
    println!("Loaded {} rules", rules.len());
    println!();

    for rule in &rules {
        println!("{:#?}", rule);
    }

    log("Configuration loaded");
    log("Firewall started");
    println!("Firewall is now running...");

    // testing
    let packet = Packet {
        source_ip: "192.168.1.25".to_string(),
        destination_ip: "8.8.8.8".to_string(),
        protocol: Protocol::TCP,
        destination_port: 443,
    };
    ex_nft::block_ip("8.8.8.8").unwrap();
    println!();
    println!("Incoming Packet");
    println!("{:#?}", packet);
    println!();

    let allowed = firewall::inspect_packet(&packet, &rules);

    println!();

    if allowed {
        println!("Packet Accepted");
    } else {
        println!("Packet Blocked");
    }

    loop {
        thread::sleep(Duration::from_secs(5));
        log("Heartbeat");
        println!("Firewall alive...");
    }
}

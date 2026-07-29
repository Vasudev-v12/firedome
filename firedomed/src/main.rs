mod logger;
mod config;
mod models;
mod rules;

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
    let test_ip = "8.8.8.8";

    if rules::check_ip(test_ip, &rules) {

        println!("{} is ALLOWED", test_ip);

    } else {

        println!("{} is BLOCKED", test_ip);

    }
    
    loop {
        thread::sleep(Duration::from_secs(5));

        log("Heartbeat");

        println!("Firewall alive...");
    }
}
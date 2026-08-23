use std::process::Command;

pub fn rm_rule(handle: &u32) -> Result<(), String> {
    let output = Command::new("sudo")
        .arg("nft")
        .arg("delete")
        .arg("rule")
        .arg("inet")
        .arg("firedome-w")
        .arg("handle")
        .arg(handle.to_string())
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        println!("Rule removed");
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

pub fn block_ip(ip: &str) -> Result<(), String> {
    let output = Command::new("sudo")
        .arg("nft")
        .arg("add")
        .arg("rule")
        .arg("inet")
        .arg("firedome-w")
        .arg("output")
        .arg("ip")
        .arg("daddr")
        .arg(ip)
        .arg("drop")
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        println!("Blocked {}", ip);
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

use crate::models::{Action, Packet, Rule, Target};

pub fn inspect_packet(packet: &Packet, rules: &[Rule]) -> bool {

    for rule in rules {

        match (&rule.action, &rule.target) {

            (Action::Block, Target::Ip(ip))
                if ip == &packet.destination_ip =>
            {
                println!("Matched BLOCK IP rule");
                return false;
            }

            (Action::Allow, Target::Ip(ip))
                if ip == &packet.destination_ip =>
            {
                println!("Matched ALLOW IP rule");
                return true;
            }

            (Action::BlockPort, Target::Port(port))
                if *port == packet.destination_port =>
            {
                println!("Matched BLOCK PORT rule");
                return false;
            }

            (Action::AllowPort, Target::Port(port))
                if *port == packet.destination_port =>
            {
                println!("Matched ALLOW PORT rule");
                return true;
            }

            _ => {}

        }

    }

    println!("No matching rule");

    true
}
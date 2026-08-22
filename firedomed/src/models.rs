//  Olde models 
//#[derive(Debug, Clone)]
// pub enum Action {
//     Allow,
//     Block,
//     AllowPort,
//     BlockPort,
// }

// #[derive(Debug, Clone)]
// pub enum Target {
//     Ip(String),
//     Port(u16),
// }

// #[derive(Debug, Clone)]
// pub struct Rule {
//     pub action: Action,
//     pub target: Target,
// }


#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Allow,
    Block,
    AllowPort,
    BlockPort,
}

#[derive(Debug, Clone)]
pub enum Target {
    Ip(String),
    Port(u16),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub action: Action,
    pub target: Target,
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub source_ip: String,
    pub destination_ip: String,
    pub protocol: Protocol,
    pub destination_port: u16,
}
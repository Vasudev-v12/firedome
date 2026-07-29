#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct Rule {
    pub action: Action,
    pub target: Target,
}
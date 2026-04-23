#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupportedProtocol {
    UDP,
    ICMP,
}

impl SupportedProtocol {
    pub const fn from_str(s: &str) -> Option<Self> {
        match s {
            s if s.eq_ignore_ascii_case("udp") => Some(Self::UDP),
            s if s.eq_ignore_ascii_case("icmp") => Some(Self::ICMP),
            _ => None,
        }
    }

    pub const fn to_str(&self) -> &'static str {
        match self {
            Self::UDP => "UDP",
            Self::ICMP => "ICMP",
        }
    }
}

impl std::fmt::Display for SupportedProtocol {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.to_str())
    }
}

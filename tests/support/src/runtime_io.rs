//! Pure parsers for structured forwarder output.

use serde_json::Value as Json;

use std::net::{SocketAddr, ToSocketAddrs};

pub fn strip_log_prefix(line: &str) -> &str {
    let trimmed = line.trim_start();
    if let Some(rest) = trimmed.strip_prefix('[')
        && let Some(index) = rest.find("] ")
    {
        return &rest[index + 2..];
    }
    trimmed
}

pub fn parse_listen_addr(line: &str) -> Option<SocketAddr> {
    const PREFIX: &str = "Listening on ";
    let address = strip_log_prefix(line)
        .strip_prefix(PREFIX)?
        .split_once(',')?
        .0
        .trim()
        .split_once(':')?
        .1;
    address
        .parse::<SocketAddr>()
        .ok()
        .or_else(|| address.to_socket_addrs().ok()?.next())
}

pub fn parse_stats_json(line: &str) -> Option<Json> {
    let candidate = strip_log_prefix(line).trim_end();
    (candidate.starts_with('{') && candidate.ends_with('}'))
        .then(|| serde_json::from_str(candidate).ok())
        .flatten()
}

pub fn parse_locked_client(line: &str) -> Option<SocketAddr> {
    const PREFIX: &str = "Locked to single client ";
    let address = strip_log_prefix(line)
        .strip_prefix(PREFIX)?
        .split_once(' ')?
        .0
        .trim();
    address
        .parse::<SocketAddr>()
        .ok()
        .or_else(|| address.to_socket_addrs().ok()?.next())
}

#[cfg(test)]
mod tests {
    use super::{parse_listen_addr, parse_locked_client, parse_stats_json};

    #[test]
    fn parses_forwarder_output_shapes() {
        assert_eq!(
            parse_listen_addr("[INFO] Listening on UDP:127.0.0.1:1234, forwarding"),
            Some("127.0.0.1:1234".parse().expect("socket address"))
        );
        assert_eq!(
            parse_locked_client("[INFO] Locked to single client 127.0.0.1:4321 (connected)"),
            Some("127.0.0.1:4321".parse().expect("socket address"))
        );
        assert_eq!(
            parse_stats_json("[INFO] {\"locked\":true}").expect("stats")["locked"],
            true
        );
    }
}

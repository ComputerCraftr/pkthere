//! UDP test-network helpers shared across integration-style test targets.

use crate::orchestrator::CLIENT_WAIT_MS;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::sync::{Mutex, OnceLock};
use std::thread;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

pub const ALL_IP_FAMILIES: [IpFamily; 2] = [IpFamily::V4, IpFamily::V6];

pub const NODE1_IPV4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
pub const NODE1_IPV4_STR: &str = "127.0.0.1";
pub const NODE2_IPV4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
pub const NODE2_IPV4_STR: &str = "127.0.0.2";
pub const NODE3_IPV4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
pub const NODE3_IPV4_STR: &str = "127.0.0.3";

fn bind_udp_client_impl(addr: SocketAddr) -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(addr)?;
    sock.set_read_timeout(Some(CLIENT_WAIT_MS))?;
    sock.set_write_timeout(Some(CLIENT_WAIT_MS))?;
    Ok(sock)
}

pub fn bind_udp_client(family: IpFamily) -> io::Result<UdpSocket> {
    match family {
        IpFamily::V4 => {
            bind_udp_client_impl(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        }
        IpFamily::V6 => bind_udp_client_impl(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            0,
            0,
            0,
        ))),
    }
}

pub fn random_unprivileged_port(family: IpFamily) -> io::Result<u16> {
    let sock = bind_udp_client(family)?;
    Ok(sock.local_addr()?.port())
}

pub fn localhost_addr(family: IpFamily, port: u16) -> SocketAddr {
    match family {
        IpFamily::V4 => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
        IpFamily::V6 => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0)),
    }
}

pub fn default_test_upstream_arg(proto: &str, addr: SocketAddr) -> String {
    if proto.eq_ignore_ascii_case("icmp") {
        render_icmp_arg(addr.ip(), 0)
    } else {
        format!("{proto}:{addr}")
    }
}

pub fn default_test_icmp_upstream_arg(ip: IpAddr) -> String {
    render_icmp_arg(ip, 0)
}

pub fn render_icmp_arg(ip: IpAddr, remote_id: u16) -> String {
    match ip {
        IpAddr::V4(ip) => format!("ICMP:{ip}:{remote_id}"),
        IpAddr::V6(ip) => format!("ICMP:[{ip}]:{remote_id}"),
    }
}

pub fn render_icmp_arg_with_reply_id(ip: IpAddr, remote_id: u16, reply_id: u16) -> String {
    match ip {
        IpAddr::V4(ip) => format!("ICMP:{ip}:{remote_id}:{reply_id}"),
        IpAddr::V6(ip) => format!("ICMP:[{ip}]:{remote_id}:{reply_id}"),
    }
}

pub fn render_canonical_ip_id(ip: IpAddr, id: u16) -> String {
    match ip {
        IpAddr::V4(ip) => format!("{ip}:{id}"),
        IpAddr::V6(ip) => format!("[{ip}]:{id}"),
    }
}

#[derive(Debug)]
pub struct LoopbackAliasGuard {
    ip: Option<Ipv4Addr>,
}

#[derive(Clone, Copy, Debug)]
struct LoopbackAliasState {
    refs: usize,
    created_by_test: bool,
}

static LOOPBACK_ALIASES: OnceLock<Mutex<HashMap<Ipv4Addr, LoopbackAliasState>>> = OnceLock::new();

fn loopback_aliases() -> &'static Mutex<HashMap<Ipv4Addr, LoopbackAliasState>> {
    LOOPBACK_ALIASES.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn ensure_loopback_ip(ip: Ipv4Addr) -> io::Result<LoopbackAliasGuard> {
    if ip == Ipv4Addr::LOCALHOST || !platform_needs_explicit_loopback_alias() {
        return Ok(LoopbackAliasGuard { ip: None });
    }

    let mut aliases = loopback_aliases()
        .lock()
        .expect("loopback alias registry lock");
    if let Some(state) = aliases.get_mut(&ip) {
        state.refs += 1;
        return Ok(LoopbackAliasGuard { ip: Some(ip) });
    }

    let already_exists = loopback_alias_exists(ip)?;
    if !already_exists {
        create_loopback_alias(ip)?;
        if !loopback_alias_exists(ip)? {
            return Err(io::Error::other(format!(
                "attempted to add loopback alias {ip}, but the OS still does not report it"
            )));
        }
    }

    aliases.insert(
        ip,
        LoopbackAliasState {
            refs: 1,
            created_by_test: !already_exists,
        },
    );
    Ok(LoopbackAliasGuard { ip: Some(ip) })
}

impl Drop for LoopbackAliasGuard {
    fn drop(&mut self) {
        let Some(ip) = self.ip.take() else {
            return;
        };

        let should_delete = {
            let mut aliases = loopback_aliases()
                .lock()
                .expect("loopback alias registry lock");
            let Some(state) = aliases.get_mut(&ip) else {
                return;
            };
            state.refs -= 1;
            if state.refs == 0 {
                let created_by_test = state.created_by_test;
                aliases.remove(&ip);
                created_by_test
            } else {
                false
            }
        };

        if should_delete && let Err(err) = delete_loopback_alias(ip) {
            eprintln!("failed to remove test-created loopback alias {ip}: {err}");
        }
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn platform_needs_explicit_loopback_alias() -> bool {
    true
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_needs_explicit_loopback_alias() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn loopback_alias_exists(ip: Ipv4Addr) -> io::Result<bool> {
    use std::process::Command;

    let output = Command::new("ifconfig").arg("lo0").output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "failed to inspect macOS lo0 while checking {ip}: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let needle = format!("inet {ip} ");
    Ok(String::from_utf8_lossy(&output.stdout).contains(&needle))
}

#[cfg(target_os = "macos")]
fn create_loopback_alias(ip: Ipv4Addr) -> io::Result<()> {
    use std::process::Command;

    let output = Command::new("sudo")
        .args([
            "-n",
            "ifconfig",
            "lo0",
            "alias",
            &ip.to_string(),
            "255.255.255.255",
        ])
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "could not add macOS loopback alias {ip}; expected passwordless sudo for `ifconfig lo0 alias`. stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

#[cfg(target_os = "macos")]
fn delete_loopback_alias(ip: Ipv4Addr) -> io::Result<()> {
    use std::process::Command;

    let output = Command::new("sudo")
        .args(["-n", "ifconfig", "lo0", "-alias", &ip.to_string()])
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "could not remove macOS loopback alias {ip}. stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

#[cfg(windows)]
fn loopback_alias_exists(ip: Ipv4Addr) -> io::Result<bool> {
    use std::process::Command;

    let ip_s = ip.to_string();
    let check = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Get-NetIPAddress -AddressFamily IPv4 -IPAddress '{}' -ErrorAction SilentlyContinue",
                ip_s
            ),
        ])
        .output()?;

    Ok(check.status.success() && !String::from_utf8_lossy(&check.stdout).trim().is_empty())
}

#[cfg(windows)]
fn create_loopback_alias(ip: Ipv4Addr) -> io::Result<()> {
    use std::process::Command;

    let ip_s = ip.to_string();
    let loopback = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetIPInterface -AddressFamily IPv4 | \
             Where-Object { $_.InterfaceAlias -like '*Loopback*' -or $_.InterfaceDescription -like '*Loopback*' } | \
             Sort-Object InterfaceMetric | \
             Select-Object -First 1 -Property InterfaceIndex,InterfaceAlias | \
             ConvertTo-Json -Compress",
        ])
        .output()?;

    if !loopback.status.success() {
        return Err(io::Error::other(format!(
            "failed to query Windows loopback interface while adding {ip_s}: {}",
            String::from_utf8_lossy(&loopback.stderr)
        )));
    }

    let loopback_json = String::from_utf8_lossy(&loopback.stdout);
    let loopback_json = loopback_json.trim();
    if loopback_json.is_empty() {
        return Err(io::Error::other(format!(
            "could not find a Windows IPv4 loopback interface to add {ip_s}"
        )));
    }

    let parsed: serde_json::Value = serde_json::from_str(loopback_json).map_err(|e| {
        io::Error::other(format!(
            "failed to parse loopback JSON `{loopback_json}`: {e}"
        ))
    })?;

    let interface_index = parsed
        .get("InterfaceIndex")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| {
            io::Error::other(format!(
                "failed to parse InterfaceIndex from `{loopback_json}`"
            ))
        })?;

    let interface_alias = parsed
        .get("InterfaceAlias")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            io::Error::other(format!(
                "failed to parse InterfaceAlias from `{loopback_json}`"
            ))
        })?;

    let add = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "New-NetIPAddress -InterfaceIndex {} -IPAddress '{}' -PrefixLength 8 -AddressFamily IPv4 -Type Unicast -PolicyStore ActiveStore -SkipAsSource $true -ErrorAction Stop",
                interface_index, ip_s
            ),
        ])
        .output()?;

    if add.status.success() {
        return Ok(());
    }

    let netsh = Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "add",
            "address",
            &format!("name={interface_alias}"),
            &format!("address={ip_s}"),
            "mask=255.0.0.0",
            "skipassource=true",
        ])
        .output()?;

    if netsh.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "failed to add Windows loopback IP {ip_s} using New-NetIPAddress and netsh. \
             New-NetIPAddress stderr: {}\nnetsh stderr: {}",
            String::from_utf8_lossy(&add.stderr),
            String::from_utf8_lossy(&netsh.stderr)
        )))
    }
}

#[cfg(windows)]
fn delete_loopback_alias(ip: Ipv4Addr) -> io::Result<()> {
    use std::process::Command;

    let ip_s = ip.to_string();
    let remove = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "Get-NetIPAddress -AddressFamily IPv4 -IPAddress '{}' -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop",
                ip_s
            ),
        ])
        .output()?;

    if remove.status.success() {
        return Ok(());
    }

    let netsh = Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "delete",
            "address",
            &format!("address={ip_s}"),
        ])
        .output()?;

    if netsh.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "failed to remove Windows loopback IP {ip_s}. Remove-NetIPAddress stderr: {}\nnetsh stderr: {}",
            String::from_utf8_lossy(&remove.stderr),
            String::from_utf8_lossy(&netsh.stderr)
        )))
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn loopback_alias_exists(_ip: Ipv4Addr) -> io::Result<bool> {
    Ok(true)
}

#[cfg(not(any(windows, target_os = "macos")))]
fn create_loopback_alias(_ip: Ipv4Addr) -> io::Result<()> {
    Ok(())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn delete_loopback_alias(_ip: Ipv4Addr) -> io::Result<()> {
    Ok(())
}

fn spawn_udp_echo_server_impl(
    addr: SocketAddr,
) -> io::Result<(SocketAddr, thread::JoinHandle<()>)> {
    let sock = UdpSocket::bind(addr)?;
    sock.set_read_timeout(Some(CLIENT_WAIT_MS))?;
    sock.set_write_timeout(Some(CLIENT_WAIT_MS))?;
    let local = sock.local_addr()?;
    let handle = thread::spawn(move || {
        let mut buf = [0u8; 65535];
        let mut connected = false;
        loop {
            if !connected {
                if let Ok((n, src)) = sock.recv_from(&mut buf)
                    && sock.connect(src).is_ok()
                {
                    connected = true;
                    let _ = sock.send(&buf[..n]);
                }
            } else if let Ok(n) = sock.recv(&mut buf) {
                let _ = sock.send(&buf[..n]);
            }
        }
    });
    Ok((local, handle))
}

pub fn spawn_udp_echo_server(family: IpFamily) -> io::Result<(SocketAddr, thread::JoinHandle<()>)> {
    match family {
        IpFamily::V4 => {
            spawn_udp_echo_server_impl(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        }
        IpFamily::V6 => spawn_udp_echo_server_impl(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            0,
            0,
            0,
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IpFamily, default_test_icmp_upstream_arg, default_test_upstream_arg, localhost_addr,
        render_canonical_ip_id, render_icmp_arg, render_icmp_arg_with_reply_id,
    };
    use std::net::{IpAddr, Ipv6Addr};

    #[test]
    fn default_test_upstream_arg_preserves_protocol_specific_shape() {
        let addr = localhost_addr(IpFamily::V4, 4444);
        for (proto, expected) in [
            ("ICMP", format!("ICMP:{}:0", super::NODE1_IPV4_STR)),
            ("UDP", format!("UDP:{}:4444", super::NODE1_IPV4_STR)),
        ] {
            assert_eq!(default_test_upstream_arg(proto, addr), expected);
        }
    }

    #[test]
    fn default_test_icmp_upstream_arg_uses_zero_id() {
        assert_eq!(
            default_test_icmp_upstream_arg(IpAddr::V4(super::NODE1_IPV4)),
            format!("ICMP:{}:0", super::NODE1_IPV4_STR)
        );
    }

    #[test]
    fn render_icmp_arg_brackets_ipv6() {
        assert_eq!(
            render_icmp_arg(IpAddr::V6(Ipv6Addr::LOCALHOST), 1234),
            "ICMP:[::1]:1234"
        );
        assert_eq!(
            render_icmp_arg_with_reply_id(IpAddr::V6(Ipv6Addr::LOCALHOST), 2002, 1001),
            "ICMP:[::1]:2002:1001"
        );
        assert_eq!(
            render_canonical_ip_id(IpAddr::V6(Ipv6Addr::LOCALHOST), 77),
            "[::1]:77"
        );
    }
}

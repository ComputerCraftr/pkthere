use pkthere_socket_policy::SocketRole;
use socket2::Type;

pub(super) const fn role_name(role: SocketRole) -> &'static str {
    match role {
        SocketRole::Listener => "listener",
        SocketRole::Upstream => "upstream",
    }
}

pub(super) fn socket_type_name(socket_type: Type) -> &'static str {
    if socket_type == Type::DGRAM {
        "dgram"
    } else if socket_type == Type::RAW {
        "raw"
    } else {
        "other"
    }
}

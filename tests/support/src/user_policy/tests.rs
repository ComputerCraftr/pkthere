use super::privilege_drop_user;
use nix::unistd;

#[test]
fn setuid_test_child_drops_back_to_the_invoking_user() {
    let real_uid = unistd::getuid();
    if real_uid.is_root() {
        let expected = std::env::var("SUDO_UID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|uid| *uid != 0)
            .map(unistd::Uid::from_raw)
            .and_then(|uid| unistd::User::from_uid(uid).ok().flatten())
            .map_or_else(|| "nobody".to_string(), |user| user.name);
        assert_eq!(privilege_drop_user(), expected);
    } else {
        let expected = unistd::User::from_uid(real_uid)
            .expect("lookup invoking UID")
            .expect("invoking user exists")
            .name;
        assert_eq!(privilege_drop_user(), expected);
    }
}

#[path = "common/policy.rs"]
mod policy;

#[test]
fn rust_source_files_stay_under_1000_lines() {
    policy::assert_rust_source_files_stay_under_1000_lines();
}

#[test]
fn no_direct_recursion_in_scoped_rust_sources() {
    policy::assert_no_direct_recursion_in_rust_sources();
}

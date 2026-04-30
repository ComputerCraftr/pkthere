#[path = "common/policy.rs"]
mod policy;

#[test]
fn rust_source_files_stay_under_1100_lines() {
    policy::assert_rust_source_files_stay_under_1100_lines();
}

#[test]
fn no_direct_recursion_in_scoped_rust_sources() {
    policy::assert_no_direct_recursion_in_rust_sources();
}

#[test]
fn blanket_dead_code_and_unused_import_allows_stay_scoped() {
    policy::assert_blanket_dead_code_and_unused_import_allows_are_scoped();
}

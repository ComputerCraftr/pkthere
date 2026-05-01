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

#[test]
fn blanket_dead_code_and_unused_import_allows_stay_scoped() {
    policy::assert_blanket_dead_code_and_unused_import_allows_are_scoped();
}

#[test]
fn no_duplicate_non_test_function_sources_in_scoped_rust_sources() {
    policy::assert_no_duplicate_function_sources_in_scoped_rust_sources();
}

#[test]
fn no_duplicate_long_test_bodies_in_scoped_rust_sources() {
    policy::assert_no_duplicate_test_bodies_in_scoped_rust_sources();
}

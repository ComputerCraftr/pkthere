mod common;

use common::{atomic_policy, harness_policy, path_naming_policy, policy, source_layout_policy};

#[test]
fn production_rust_items_have_bounded_complexity() {
    policy::assert_rust_items_have_bounded_complexity();
}

#[test]
fn unsupported_test_platforms_use_explicit_ignore_attributes() {
    policy::assert_tests_do_not_return_without_running();
}

#[test]
fn source_layout_policy_engine_is_self_consistent() {
    source_layout_policy::assert_engine_fixtures();
}

#[test]
fn internal_source_paths_use_snake_case() {
    path_naming_policy::assert_source_paths_follow_naming_policy();
}

#[test]
fn tests_do_not_depend_on_ipv4_loopback_aliases() {
    policy::assert_tests_do_not_use_loopback_aliases();
}

#[test]
fn rust_sources_use_platform_temporary_directories() {
    policy::assert_rust_sources_use_platform_temporary_directories();
}

#[test]
fn module_constants_are_grouped_at_the_top() {
    policy::assert_module_constants_are_grouped_at_the_top();
}

#[test]
fn syntactic_direct_recursion_is_forbidden() {
    policy::assert_syntactic_direct_recursion_is_forbidden();
}

#[test]
fn dead_code_allows_are_forbidden() {
    policy::assert_dead_code_allows_are_forbidden();
}

#[test]
fn no_wildcard_imports_in_project_rust_sources() {
    policy::assert_no_wildcard_imports_in_project_rust_sources();
}

#[test]
fn no_duplicate_function_logic_in_workspace() {
    policy::assert_no_duplicate_function_logic_in_workspace();
}

#[test]
fn rust_source_semantic_policies_are_ast_backed() {
    policy::assert_rust_source_semantic_policies_are_ast_backed();
}

#[test]
fn portable_build_configuration_is_structurally_valid() {
    policy::assert_portable_build_configuration();
}

#[test]
fn endpoint_and_socket_authority_is_centralized() {
    policy::assert_endpoint_and_socket_authority_is_centralized();
}

#[test]
fn manager_version_authority_is_transactional() {
    policy::assert_manager_version_authority_is_transactional();
}

#[test]
fn stats_and_required_evidence_have_single_fail_closed_authorities() {
    policy::assert_stats_and_required_evidence_fail_closed();
}

#[test]
fn production_invariants_do_not_disappear_in_release_builds() {
    policy::assert_production_code_has_no_debug_only_assertions();
}

#[test]
fn production_runtime_has_no_explicit_panic_surfaces() {
    policy::assert_production_code_has_no_explicit_panic_surfaces();
}

#[test]
fn failure_containment_paths_are_structurally_fail_closed() {
    policy::assert_failure_containment_is_fail_closed();
}

#[test]
fn interior_mutability_authorities_are_registered() {
    policy::assert_interior_mutability_authorities_are_registered();
}

#[test]
fn production_protocols_use_explicit_publication_ordering() {
    policy::assert_production_protocols_use_explicit_publication_ordering();
}

#[test]
fn production_types_have_no_mutable_test_only_authority() {
    policy::assert_production_types_have_no_mutable_test_only_authority();
}

#[test]
fn synchronization_authorities_have_a_complete_graph_and_publication_catalog() {
    atomic_policy::assert_synchronization_authority_catalog_is_complete();
}

#[test]
fn rollback_and_recovery_implementations_have_single_authorities() {
    atomic_policy::assert_transaction_recovery_authorities_are_unique();
}

#[test]
fn shared_worker_flow_state_has_one_payload_and_sequence_authority() {
    atomic_policy::assert_shared_worker_flow_authorities_are_unique();
}

#[test]
fn stable_forwarding_requires_directional_non_writer_permits() {
    atomic_policy::assert_stable_forwarding_requires_directional_permits();
}

#[test]
fn test_harness_lifecycle_boundaries_are_centralized() {
    harness_policy::assert_test_harness_lifecycle_boundaries();
}

#[test]
fn native_ci_uses_shared_raw_capability_and_test_runners() {
    policy::assert_ci_workflow_has_executable_semantics();
}

#[test]
fn release_evidence_tests_execute_required_production_semantics() {
    policy::assert_release_evidence_tests_execute_required_semantics();
}

#[test]
fn protocol_helpers_do_not_emit_unrequested_debug_logs() {
    policy::assert_protocol_helpers_do_not_emit_unrequested_debug_logs();
}

#[test]
fn policy_is_ast_backed_and_ignores_closure_returns() {
    let syntax = syn::parse_file(
        r#"
        #[test]
        fn fake_green() {
            if !supported() { return; }
        }

        #[test]
        fn real_test() {
            let callback = || { return; };
            callback();
            assert!(true);
        }
        "#,
    )
    .expect("parse return-policy fixture");

    assert_eq!(
        super::test_execution_policy::test_functions_with_bare_return(&syntax),
        ["fake_green"]
    );
}

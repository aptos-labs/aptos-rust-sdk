//! Compile-time tests for procedural macros using trybuild.

#[test]
fn ui_tests() {
    let t = trybuild::TestCases::new();
    // Tests that should pass compilation
    t.pass("tests/ui/pass/*.rs");
    // Tests that should fail compilation (with expected error messages)
    t.compile_fail("tests/ui/fail/*.rs");
}

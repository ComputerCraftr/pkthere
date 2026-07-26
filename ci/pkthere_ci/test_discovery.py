"""Fail-closed parsing of Rust test-harness listings."""

from collections import Counter


def listed_rust_tests(output: str) -> frozenset[str]:
    return frozenset(listed_rust_test_counts(output))


def listed_rust_test_counts(output: str) -> Counter[str]:
    suffix = ": test"
    return Counter(
        line.removesuffix(suffix).strip()
        for line in output.splitlines()
        if line.strip().endswith(suffix)
    )


def require_listed_rust_test(discovered: frozenset[str], test_name: str) -> None:
    if test_name not in discovered:
        raise RuntimeError(f"required exact test was not discovered: {test_name}")


def require_exactly_one_listed_rust_test(output: str, test_name: str) -> None:
    count = listed_rust_test_counts(output)[test_name]
    if count != 1:
        raise RuntimeError(
            f"required exact test must be listed once: {test_name} (found {count})"
        )


def require_nonempty_rust_tests(discovered: frozenset[str], owner: str) -> None:
    if not discovered:
        raise RuntimeError(f"{owner} contains zero tests")

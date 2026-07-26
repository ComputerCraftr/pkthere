"""macOS profiling policy tests."""

import tempfile
import unittest
from pathlib import Path

from ci.pkthere_ci.macos_profile import (
    ENCODED_FLAG_SEPARATOR,
    deterministic_bundle_manifest,
    intentional_flags,
    parse_dwarfdump_uuids,
    parse_rustc_host,
    profiling_environment,
    profiling_paths,
    resolve_dwarf_payload,
)


class MacosProfilePolicyTests(unittest.TestCase):
    def test_complete_encoded_flags_preserve_cpu_policy_and_frame_pointers(
        self,
    ) -> None:
        source = {
            "PATH": "/tools",
            "RUSTFLAGS": "secret-host-flags",
            "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS": "secret-target-flags",
        }
        with tempfile.TemporaryDirectory() as directory:
            target_dir = Path(directory) / "profile-target"
            environment, removed, flags = profiling_environment(
                source,
                cpu_policy="portable",
                target_dir=target_dir,
            )

        self.assertEqual(
            flags,
            (
                "-C",
                "target-cpu=generic",
                "-C",
                "force-frame-pointers=yes",
            ),
        )
        self.assertEqual(
            environment["CARGO_ENCODED_RUSTFLAGS"],
            ENCODED_FLAG_SEPARATOR.join(flags),
        )
        self.assertEqual(environment["CARGO_TARGET_DIR"], str(target_dir))
        self.assertEqual(
            removed,
            (
                "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS",
                "RUSTFLAGS",
            ),
        )
        self.assertNotIn("secret-host-flags", repr(environment))
        self.assertNotIn("secret-target-flags", repr(environment))

    def test_portable_and_native_artifacts_use_separate_target_directories(
        self,
    ) -> None:
        root = Path("/repo")
        evidence = Path("/evidence")
        portable = profiling_paths(
            root,
            evidence,
            "aarch64-apple-darwin",
            "portable",
        )
        native = profiling_paths(
            root,
            evidence,
            "aarch64-apple-darwin",
            "native",
        )

        self.assertNotEqual(portable.target_dir, native.target_dir)
        self.assertEqual(
            portable.binary,
            root
            / "target/macos_profile/aarch64-apple-darwin/portable"
            / "aarch64-apple-darwin/profiling/pkthere",
        )
        self.assertEqual(
            portable.dwarf_directory,
            portable.dsym / "Contents/Resources/DWARF",
        )

    def test_host_and_uuid_parsers_fail_closed(self) -> None:
        self.assertEqual(
            parse_rustc_host("rustc 1.97.1\nhost: aarch64-apple-darwin\n"),
            "aarch64-apple-darwin",
        )
        with self.assertRaisesRegex(ValueError, "omitted"):
            parse_rustc_host("rustc 1.97.1\n")
        temporary_binary = Path(tempfile.gettempdir()) / "pkthere"
        self.assertEqual(
            parse_dwarfdump_uuids(
                "UUID: 12345678-1234-1234-1234-123456789abc "
                f"(arm64) {temporary_binary}\n"
            ),
            frozenset({"12345678-1234-1234-1234-123456789ABC"}),
        )

    def test_bundle_manifest_is_sorted_and_content_addressed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle / "z").write_bytes(b"last")
            (bundle / "a").write_bytes(b"first")

            first, first_digest = deterministic_bundle_manifest(bundle)
            second, second_digest = deterministic_bundle_manifest(bundle)

        self.assertEqual(first, second)
        self.assertEqual(first_digest, second_digest)
        self.assertLess(first.index('"path": "a"'), first.index('"path": "z"'))
        self.assertEqual(
            intentional_flags("native"),
            (
                "-C",
                "target-cpu=native",
                "-C",
                "force-frame-pointers=yes",
            ),
        )

    def test_dwarf_payload_resolution_requires_exactly_one_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = profiling_paths(
                root,
                root / "evidence",
                "aarch64-apple-darwin",
                "portable",
            )
            paths.dwarf_directory.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "exactly one"):
                resolve_dwarf_payload(paths)

            payload = paths.dwarf_directory / "pkthere-hash"
            payload.write_bytes(b"dwarf")
            self.assertEqual(resolve_dwarf_payload(paths), payload)

            (paths.dwarf_directory / "other").write_bytes(b"dwarf")
            with self.assertRaisesRegex(ValueError, "exactly one"):
                resolve_dwarf_payload(paths)

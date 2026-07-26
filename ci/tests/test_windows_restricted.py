"""Tests for Windows restricted-token process isolation."""

from __future__ import annotations

import unittest
from ctypes import wintypes
from typing import Any

from ci.pkthere_ci.windows_restricted import (
    SECURITY_IDENTIFICATION,
    _restricted_token,
)


class _Kernel32:
    def __init__(self) -> None:
        self.closed: list[int] = []

    @staticmethod
    def GetCurrentProcess() -> int:
        return 1

    def CloseHandle(self, handle: wintypes.HANDLE) -> bool:
        if handle.value is None:
            raise AssertionError("test received a null handle")
        self.closed.append(handle.value)
        return True


class _Advapi32:
    def __init__(self) -> None:
        self.membership_token: int | None = None
        self.duplicate_level: int | None = None

    @staticmethod
    def OpenProcessToken(_process: int, _access: int, output: Any) -> bool:
        output._obj.value = 11
        return True

    @staticmethod
    def CreateWellKnownSid(
        _kind: int, _domain: object, _storage: object, _size: object
    ) -> bool:
        return True

    @staticmethod
    def CreateRestrictedToken(
        _current: wintypes.HANDLE,
        _flags: int,
        _disabled_count: int,
        _disabled: object,
        _deleted_count: int,
        _deleted: object,
        _restricted_count: int,
        _restricted: object,
        output: Any,
    ) -> bool:
        output._obj.value = 22
        return True

    def DuplicateToken(self, token: wintypes.HANDLE, level: int, output: Any) -> bool:
        if token.value != 22:
            return False
        self.duplicate_level = level
        output._obj.value = 33
        return True

    def CheckTokenMembership(
        self, token: wintypes.HANDLE, _sid: object, enabled: Any
    ) -> bool:
        if token.value is None:
            raise AssertionError("membership check received a null token")
        self.membership_token = token.value
        enabled._obj.value = False
        return True


class WindowsRestrictedTokenTests(unittest.TestCase):
    def test_membership_check_uses_a_derived_impersonation_token(self) -> None:
        kernel32 = _Kernel32()
        advapi32 = _Advapi32()

        restricted = _restricted_token(kernel32, advapi32)

        self.assertEqual(restricted.value, 22)
        self.assertEqual(advapi32.duplicate_level, SECURITY_IDENTIFICATION)
        self.assertEqual(advapi32.membership_token, 33)
        self.assertEqual(kernel32.closed, [33, 11])


if __name__ == "__main__":
    unittest.main()

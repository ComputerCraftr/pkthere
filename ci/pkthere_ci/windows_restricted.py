"""Run Windows reality probes with administrator authority removed."""

from __future__ import annotations

import ctypes
import math
import os
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from ctypes import wintypes
from pathlib import Path
from typing import Any, BinaryIO, cast

from .command_runner import CommandResult, CommandTimeoutError

CREATE_NEW_PROCESS_GROUP = 0x0000_0200
CREATE_UNICODE_ENVIRONMENT = 0x0000_0400
DISABLE_MAX_PRIVILEGE = 0x0000_0001
ERROR_PRIVILEGE_NOT_HELD = 1314
LOGON_WITH_PROFILE = 0x0000_0001
SE_GROUP_USE_FOR_DENY_ONLY = 0x0000_0010
SECURITY_IDENTIFICATION = 1
STARTF_USESTDHANDLES = 0x0000_0100
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
WIN_BUILTIN_ADMINISTRATORS_SID = 26


class StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("reserved", wintypes.LPWSTR),
        ("desktop", wintypes.LPWSTR),
        ("title", wintypes.LPWSTR),
        ("x", wintypes.DWORD),
        ("y", wintypes.DWORD),
        ("x_size", wintypes.DWORD),
        ("y_size", wintypes.DWORD),
        ("x_count_chars", wintypes.DWORD),
        ("y_count_chars", wintypes.DWORD),
        ("fill_attribute", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("show_window", wintypes.WORD),
        ("reserved_count", wintypes.WORD),
        ("reserved_bytes", ctypes.POINTER(ctypes.c_ubyte)),
        ("standard_input", wintypes.HANDLE),
        ("standard_output", wintypes.HANDLE),
        ("standard_error", wintypes.HANDLE),
    ]


class ProcessInformation(ctypes.Structure):
    _fields_ = [
        ("process", wintypes.HANDLE),
        ("thread", wintypes.HANDLE),
        ("process_id", wintypes.DWORD),
        ("thread_id", wintypes.DWORD),
    ]


class SidAndAttributes(ctypes.Structure):
    _fields_ = [("sid", wintypes.LPVOID), ("attributes", wintypes.DWORD)]


def run_restricted_windows(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    cwd: Path | None,
    env: Mapping[str, str] | None,
    check: bool,
    capture_output: bool,
) -> CommandResult:
    """Create a child token with admin SIDs disabled and privileges removed."""
    if os.name != "nt":
        raise RuntimeError("restricted Windows execution requires a Windows host")
    if not capture_output:
        raise ValueError("restricted Windows execution requires captured output")
    if not command:
        raise ValueError("restricted Windows execution requires a command")

    kernel32 = _windows_library("kernel32")
    advapi32 = _windows_library("advapi32")
    _configure_signatures(kernel32, advapi32)
    token = _restricted_token(kernel32, advapi32)
    argv = tuple(command)
    started = time.monotonic()
    process = ProcessInformation()
    try:
        with (
            tempfile.TemporaryFile(mode="w+b") as stdout_file,
            tempfile.TemporaryFile(mode="w+b") as stderr_file,
            open(os.devnull, "rb") as stdin_file,
        ):
            try:
                handles = _inheritable_standard_handles(
                    stdin_file, stdout_file, stderr_file
                )
                startup = StartupInfo(
                    cb=ctypes.sizeof(StartupInfo),
                    flags=STARTF_USESTDHANDLES,
                    standard_input=handles[0],
                    standard_output=handles[1],
                    standard_error=handles[2],
                )
                command_line = ctypes.create_unicode_buffer(
                    subprocess.list2cmdline(argv)
                )
                environment = _environment_block(os.environ if env is None else env)
                flags = CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT
                _create_restricted_process(
                    advapi32,
                    token,
                    command_line,
                    flags,
                    environment,
                    cwd,
                    startup,
                    process,
                )
                _close_handle(kernel32, process.thread)
                process.thread = None
                wait_milliseconds = min(math.ceil(timeout_seconds * 1000), 0xFFFF_FFFE)
                wait_result = kernel32.WaitForSingleObject(
                    process.process, wait_milliseconds
                )
                if wait_result == WAIT_TIMEOUT:
                    kernel32.TerminateProcess(process.process, 1)
                    kernel32.WaitForSingleObject(process.process, 5_000)
                    result = _process_result(
                        kernel32,
                        process,
                        argv,
                        stdout_file,
                        stderr_file,
                        started,
                    )
                    raise CommandTimeoutError(result, timeout_seconds)
                if wait_result != WAIT_OBJECT_0:
                    raise _windows_error("WaitForSingleObject")
                result = _process_result(
                    kernel32,
                    process,
                    argv,
                    stdout_file,
                    stderr_file,
                    started,
                )
            finally:
                for file in (stdin_file, stdout_file, stderr_file):
                    os.set_inheritable(file.fileno(), False)
                _close_handle(kernel32, process.thread)
                _close_handle(kernel32, process.process)
    finally:
        _close_handle(kernel32, token)

    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode,
            result.argv,
            output=result.stdout,
            stderr=result.stderr,
        )
    return result


def _windows_library(name: str) -> Any:
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise RuntimeError("Windows API loading is unavailable")
    return loader(name, use_last_error=True)


def _configure_signatures(kernel32: Any, advapi32: Any) -> None:
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.CreateWellKnownSid.argtypes = [
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.CreateWellKnownSid.restype = wintypes.BOOL
    advapi32.CreateRestrictedToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(SidAndAttributes),
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.CreateRestrictedToken.restype = wintypes.BOOL
    advapi32.DuplicateToken.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.DuplicateToken.restype = wintypes.BOOL
    advapi32.CheckTokenMembership.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.CheckTokenMembership.restype = wintypes.BOOL
    advapi32.CreateProcessAsUserW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPCWSTR,
        ctypes.POINTER(StartupInfo),
        ctypes.POINTER(ProcessInformation),
    ]
    advapi32.CreateProcessAsUserW.restype = wintypes.BOOL
    advapi32.CreateProcessWithTokenW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPCWSTR,
        ctypes.POINTER(StartupInfo),
        ctypes.POINTER(ProcessInformation),
    ]
    advapi32.CreateProcessWithTokenW.restype = wintypes.BOOL


def _restricted_token(kernel32: Any, advapi32: Any) -> wintypes.HANDLE:
    current = wintypes.HANDLE()
    access = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), access, ctypes.byref(current)
    ):
        raise _windows_error("OpenProcessToken")
    restricted = wintypes.HANDLE()
    try:
        sid_storage = ctypes.create_string_buffer(68)
        sid_size = wintypes.DWORD(ctypes.sizeof(sid_storage))
        if not advapi32.CreateWellKnownSid(
            WIN_BUILTIN_ADMINISTRATORS_SID,
            None,
            sid_storage,
            ctypes.byref(sid_size),
        ):
            raise _windows_error("CreateWellKnownSid")
        disabled = SidAndAttributes(
            sid=ctypes.cast(sid_storage, wintypes.LPVOID),
            attributes=SE_GROUP_USE_FOR_DENY_ONLY,
        )
        if not advapi32.CreateRestrictedToken(
            current,
            DISABLE_MAX_PRIVILEGE,
            1,
            ctypes.byref(disabled),
            0,
            None,
            0,
            None,
            ctypes.byref(restricted),
        ):
            raise _windows_error("CreateRestrictedToken")
        membership_token = wintypes.HANDLE()
        if not advapi32.DuplicateToken(
            restricted,
            SECURITY_IDENTIFICATION,
            ctypes.byref(membership_token),
        ):
            raise _windows_error("DuplicateToken")
        try:
            admin_enabled = wintypes.BOOL()
            if not advapi32.CheckTokenMembership(
                membership_token,
                ctypes.cast(sid_storage, wintypes.LPVOID),
                ctypes.byref(admin_enabled),
            ):
                raise _windows_error("CheckTokenMembership")
            if admin_enabled.value:
                raise RuntimeError(
                    "restricted Windows token retained administrator membership"
                )
        finally:
            _close_handle(kernel32, membership_token)
        return restricted
    except BaseException:
        _close_handle(kernel32, restricted)
        raise
    finally:
        _close_handle(kernel32, current)


def _inheritable_standard_handles(
    stdin_file: BinaryIO,
    stdout_file: BinaryIO,
    stderr_file: BinaryIO,
) -> tuple[wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE]:
    import msvcrt

    files = (stdin_file, stdout_file, stderr_file)
    for file in files:
        os.set_inheritable(file.fileno(), True)
    windows_msvcrt = cast(Any, msvcrt)
    get_osfhandle = windows_msvcrt.get_osfhandle
    return (
        wintypes.HANDLE(get_osfhandle(stdin_file.fileno())),
        wintypes.HANDLE(get_osfhandle(stdout_file.fileno())),
        wintypes.HANDLE(get_osfhandle(stderr_file.fileno())),
    )


def _environment_block(environment: Mapping[str, str]) -> ctypes.Array[ctypes.c_wchar]:
    entries = []
    for key, value in environment.items():
        if "\0" in key or "\0" in value:
            raise ValueError("Windows environment contains a NUL byte")
        entries.append(f"{key}={value}")
    block = "\0".join(sorted(entries, key=str.upper)) + "\0\0"
    return ctypes.create_unicode_buffer(block)


def _create_restricted_process(
    advapi32: Any,
    token: wintypes.HANDLE,
    command_line: ctypes.Array[ctypes.c_wchar],
    flags: int,
    environment: ctypes.Array[ctypes.c_wchar],
    cwd: Path | None,
    startup: StartupInfo,
    process: ProcessInformation,
) -> None:
    directory = None if cwd is None else str(cwd)
    rendered_command = command_line.value
    created = advapi32.CreateProcessAsUserW(
        token,
        None,
        command_line,
        None,
        None,
        True,
        flags,
        environment,
        directory,
        ctypes.byref(startup),
        ctypes.byref(process),
    )
    if created:
        return
    windows_ctypes = cast(Any, ctypes)
    if windows_ctypes.get_last_error() != ERROR_PRIVILEGE_NOT_HELD:
        raise _windows_error("CreateProcessAsUserW")
    retry_command_line = ctypes.create_unicode_buffer(rendered_command)
    if not advapi32.CreateProcessWithTokenW(
        token,
        LOGON_WITH_PROFILE,
        None,
        retry_command_line,
        flags,
        environment,
        directory,
        ctypes.byref(startup),
        ctypes.byref(process),
    ):
        raise _windows_error("CreateProcessWithTokenW")


def _process_result(
    kernel32: Any,
    process: ProcessInformation,
    argv: tuple[str, ...],
    stdout_file: BinaryIO,
    stderr_file: BinaryIO,
    started: float,
) -> CommandResult:
    exit_code = wintypes.DWORD()
    if not kernel32.GetExitCodeProcess(process.process, ctypes.byref(exit_code)):
        raise _windows_error("GetExitCodeProcess")
    stdout_file.seek(0)
    stderr_file.seek(0)
    return CommandResult(
        argv=argv,
        returncode=int(exit_code.value),
        stdout=stdout_file.read().decode(errors="replace"),
        stderr=stderr_file.read().decode(errors="replace"),
        duration_seconds=time.monotonic() - started,
    )


def _close_handle(kernel32: Any, handle: wintypes.HANDLE | None) -> None:
    if handle:
        kernel32.CloseHandle(handle)


def _windows_error(operation: str) -> OSError:
    windows_ctypes = cast(Any, ctypes)
    code = windows_ctypes.get_last_error()
    message = windows_ctypes.FormatError(code)
    return OSError(code, f"{operation} failed: {message}")

#!/usr/bin/env bash
set -euo pipefail

privileged_binary="${1:?usage: revoke_raw_capability.sh PRIVILEGED_BINARY}"

run_privileged() {
	if ((EUID == 0)); then
		"$@"
	else
		sudo "$@"
	fi
}

if [[ -e "$privileged_binary" ]]; then
	run_privileged rm -f -- "$privileged_binary"
fi

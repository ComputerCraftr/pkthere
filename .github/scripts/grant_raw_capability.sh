#!/usr/bin/env bash
set -euo pipefail

source_binary="${1:?usage: grant_raw_capability.sh SOURCE [DESTINATION]}"
destination_binary="${2:?usage: grant_raw_capability.sh SOURCE DESTINATION}"

run_privileged() {
	if ((EUID == 0)); then
		"$@"
	else
		sudo "$@"
	fi
}

if [[ ! -x "$source_binary" ]]; then
	echo "RAW capability source is missing or not executable: $source_binary" >&2
	exit 1
fi
if [[ "$source_binary" == "$destination_binary" ]]; then
	echo "RAW capability destination must differ from its immutable source" >&2
	exit 1
fi
mkdir -p "$(dirname "$destination_binary")"
cp "$source_binary" "$destination_binary"

kernel_name="$(uname -s)"
case "$kernel_name" in
	Linux)
		run_privileged setcap cap_net_raw+ep "$destination_binary"
		getcap "$destination_binary"
		;;
	macOS | Darwin)
		run_privileged chown root "$destination_binary"
		run_privileged chmod u+s "$destination_binary"
		ls -l "$destination_binary"
		;;
	FreeBSD)
		run_privileged chown root:wheel "$destination_binary"
		run_privileged chmod u+s "$destination_binary"
		ls -l "$destination_binary"
		;;
	*)
		echo "RAW capability installation is unsupported on $kernel_name" >&2
		exit 1
		;;
esac

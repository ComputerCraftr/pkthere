#!/usr/bin/env bash
set -euo pipefail

source_binary="${1:?usage: grant_raw_capability.sh SOURCE [DESTINATION]}"
destination_binary="${2:-$source_binary}"

if [[ ! -x "$source_binary" ]]; then
	echo "RAW capability source is missing or not executable: $source_binary" >&2
	exit 1
fi
if [[ "$source_binary" != "$destination_binary" ]]; then
	mkdir -p "$(dirname "$destination_binary")"
	cp "$source_binary" "$destination_binary"
fi

case "${RUNNER_OS:-$(uname -s)}" in
	Linux)
		sudo setcap cap_net_raw+ep "$destination_binary"
		getcap "$destination_binary"
		;;
	macOS | Darwin)
		sudo chown root "$destination_binary"
		sudo chmod u+s "$destination_binary"
		ls -l "$destination_binary"
		;;
	*)
		echo "RAW capability installation is unsupported on ${RUNNER_OS:-$(uname -s)}" >&2
		exit 1
		;;
esac

#!/bin/sh
set -eu

version="${1:?usage: prepare_freebsd_ci.sh VERSION}"
if [ "$version" != "v1" ]; then
	echo "unsupported FreeBSD CI preparation version: $version" >&2
	exit 1
fi

pkg install -y bash git python313 rust
if ! pw usershow pkthere-ci >/dev/null 2>&1; then
	pw useradd pkthere-ci -m -s /bin/sh
fi

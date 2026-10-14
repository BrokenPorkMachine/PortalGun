#!/bin/sh
# Run the CVE-2025-43529 PoC against a jsc shell.
#
#   ./run.sh                      # uses `jsc` from PATH
#   WEBKIT_JSC=/path/to/jsc ./run.sh
#   JSC_FLAGS="--useZombieMode=true" WEBKIT_JSC=... ./run.sh
#
# Requires a *vulnerable* jsc build: WebKit revision <= 304601
# (i.e. the parent of commit b21a503 / bug 302502).

set -eu
cd "$(dirname "$0")"

JSC="${WEBKIT_JSC:-jsc}"

# Concurrent GC is required: the bug lives in the race between the mutator and
# the marker thread.
# shellcheck disable=SC2086
exec "$JSC" --useConcurrentGC=true ${JSC_FLAGS:-} poc.js

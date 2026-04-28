#!/bin/bash
# sccache wrapper for cross-rs/cross containers
#
# Pre-creates output directories under /target before delegating to
# sccache. cross runs with --user + Docker volume mount at /target,
# which can prevent sccache/rustc from creating the necessary directory
# tree. We scan args for /target/ paths and mkdir -p their parent to
# ensure rustc can write there.

set -euo pipefail

for arg in "$@"; do
    # Match any arg containing /target/ (handles standalone paths,
    # --emit=dep-info=/target/..., dep-info=/target/..., etc.)
    if [[ "$arg" == *"/target/"* ]]; then
        # Strip everything before /target/ to get the absolute path
        local tgt="${arg#*/target/}"
        mkdir -p "/target/$(dirname "$tgt")" 2>/dev/null || true
    fi
done

exec /usr/bin/sccache "$@"

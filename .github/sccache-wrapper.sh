#!/bin/bash
# sccache wrapper for cross-rs/cross containers
#
# Problem: sccache inside cross Docker containers with --user fails when
# rustc tries to write .d files to /target/.../deps/ because the output
# directory structure may not exist (Docker volume mount + --user prevents
# sccache from creating deep paths in a single mkdir call).
#
# This wrapper pre-creates the output directory tree before delegating
# to sccache, matching what rustc would normally do on its own.

set -euo pipefail

# Find --out-dir argument and ensure it exists with deps/ subdirectory
while [ $# -gt 0 ]; do
    case "$1" in
        --out-dir)
            if [ -n "${2:-}" ]; then
                dir="$2"
                mkdir -p "$dir/deps"
            fi
            ;;
        --out-dir=*)
            dir="${1#*=}"
            mkdir -p "$dir/deps"
            ;;
    esac
    shift
done

exec /usr/bin/sccache "$@"

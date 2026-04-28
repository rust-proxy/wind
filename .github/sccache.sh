#!/bin/bash
#
# Install sccache from GitHub releases.
# Assumes curl is already installed in the image.
# Usage: sccache.sh <target-triple>
#   e.g. sccache.sh x86_64-unknown-linux-musl

set -x
set -euo pipefail

main() {
    local triple="${1}"
    local version="v0.12.0"
    local url="https://github.com/mozilla/sccache/releases/download/${version}/sccache-${version}-${triple}.tar.gz"
    local td

    td="$(mktemp -d)"
    pushd "${td}"

    curl -LSfs "${url}" -o sccache.tar.gz
    tar -xzf sccache.tar.gz
    cp "sccache-${version}-${triple}/sccache" "/usr/bin/sccache"
    chmod +x "/usr/bin/sccache"

    popd
    rm -rf "${td}"
    rm -f "${0}"
}

main "${@}"

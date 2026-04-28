ARG CROSS_BASE_IMAGE=scratch
ARG DEBIAN_FRONTEND=noninteractive

FROM $CROSS_BASE_IMAGE

# Install clang/llvm for C compilation (aws-lc-sys GCC memcmp bug workaround)
# Also install sccache binary for manual cache ops and future use.
# RUSTC_WRAPPER is deliberately NOT set: inside cross containers with --user,
# sccache's server mode interferes with rustc's ability to create output
# directories under /target (which is a Docker volume mount owned by root).
# Native (non-cross) builds use the host sccache via mozilla-actions/sccache-action.
COPY .github/sccache.sh /
RUN apt-get update && \
    apt-get install -y --no-install-recommends clang llvm curl ca-certificates && \
    chmod +x /sccache.sh && \
    arch=$(uname -m) && \
    case "$arch" in \
      x86_64)  triple="x86_64-unknown-linux-musl" ;; \
      aarch64) triple="aarch64-unknown-linux-musl" ;; \
      armv7l|armv7) triple="armv7-unknown-linux-musleabi" ;; \
      i686|i586) triple="i686-unknown-linux-musl" ;; \
      *) echo "FATAL: unsupported architecture for sccache: $arch" && exit 1 ;; \
    esac && \
    echo "Detected arch=$arch, downloading sccache for $triple" && \
    /sccache.sh "$triple" && \
    apt-get purge -y curl ca-certificates && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

ENV CC=clang \
    CXX=clang++ \
    AR=llvm-ar

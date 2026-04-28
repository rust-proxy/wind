ARG CROSS_BASE_IMAGE=scratch
ARG DEBIAN_FRONTEND=noninteractive

FROM $CROSS_BASE_IMAGE

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
    AR=llvm-ar \
    RUSTC_WRAPPER="/usr/bin/sccache"

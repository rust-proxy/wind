ARG CROSS_BASE_IMAGE=scratch
ARG DEBIAN_FRONTEND=noninteractive

FROM $CROSS_BASE_IMAGE

COPY .github/sccache.sh /

RUN apt-get update && \
    apt-get install -y --no-install-recommends clang llvm && \
    rm -rf /var/lib/apt/lists/* && \
    chmod +x /sccache.sh && \
    /sccache.sh "x86_64-unknown-linux-musl"

ENV CC=clang \
    CXX=clang++ \
    AR=llvm-ar \
    RUSTC_WRAPPER="/usr/bin/sccache" \
    SCCACHE_DIR="/tmp/sccache"

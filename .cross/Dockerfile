ARG CROSS_BASE_IMAGE=scratch
ARG DEBIAN_FRONTEND=noninteractive

FROM $CROSS_BASE_IMAGE

ARG CROSS_BASE_IMAGE

COPY .github/sccache.sh /

RUN apt-get update && \
    apt-get install -y --no-install-recommends clang llvm && \
    rm -rf /var/lib/apt/lists/* && \
    target="${CROSS_BASE_IMAGE##*/}" && \
    chmod +x /sccache.sh && \
    /sccache.sh "${target%%:*}"

ENV CC=clang \
    CXX=clang++ \
    AR=llvm-ar \
    RUSTC_WRAPPER="/usr/bin/sccache"

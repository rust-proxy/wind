ARG CROSS_BASE_IMAGE=scratch
ARG DEBIAN_FRONTEND=noninteractive
FROM $CROSS_BASE_IMAGE

RUN apt-get update && \
    apt-get install -y --no-install-recommends clang llvm && \
    rm -rf /var/lib/apt/lists/*

ENV CC=clang
ENV CXX=clang++
ENV AR=llvm-ar

COPY .github/sccache.sh /
ARG CROSS_BASE_IMAGE
RUN target="${CROSS_BASE_IMAGE##*/}" && /sccache.sh "${target%%:*}"

ENV RUSTC_WRAPPER="/usr/bin/sccache"
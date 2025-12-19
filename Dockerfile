FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
    build-essential \
    mingw-w64 \
    cmake \
    pkg-config \
    libssl-dev \
    debhelper \
    devscripts \
    dh-make \
    dh-cmake \
    quilt \
    git \
    libdbus-1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build-env

CMD ["/usr/bin/bash", "build.sh"]
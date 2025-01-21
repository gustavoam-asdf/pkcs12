FROM ghcr.io/napi-rs/napi-rs/nodejs-rust:lts-debian

RUN sudo apt-get install pkg-config libssl-dev -y
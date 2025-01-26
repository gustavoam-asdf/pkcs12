FROM ghcr.io/napi-rs/napi-rs/nodejs-rust:lts-alpine

RUN apk add pkgconfig openssl-dev
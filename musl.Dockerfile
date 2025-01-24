FROM ghcr.io/napi-rs/napi-rs/nodejs-rust:lts-alpine

# * This command install openssl-dev v3 but for compatibility with the most used p12 certificates in peru, I need to install v1.1
# RUN apk add pkgconfig openssl-dev

# TODO: Add a package that uses openssl 1 as a different package or different version
RUN echo "http://dl-cdn.alpinelinux.org/alpine/v3.15/main" > /etc/apk/repositories
RUN echo "http://dl-cdn.alpinelinux.org/alpine/v3.15/community" >> /etc/apk/repositories

RUN apk update
RUN apk add pkgconfig openssl-dev

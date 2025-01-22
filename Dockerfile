FROM ghcr.io/napi-rs/napi-rs/nodejs-rust:lts-debian

RUN sudo apt-get install pkg-config libssl-dev -y

RUN mkdir /usr/x86_64-unknown-linux-gnu/include/openssl

RUN cp -r /usr/include/openssl/* /usr/x86_64-unknown-linux-gnu/include/openssl
RUN cp -r /usr/include/x86_64-linux-gnu/openssl/* /usr/x86_64-unknown-linux-gnu/include/openssl

RUN cp -r /usr/lib/x86_64-linux-gnu/libssl.so* /usr/x86_64-unknown-linux-gnu/lib/
RUN cp -r /usr/lib/x86_64-linux-gnu/libcrypto.so* /usr/x86_64-unknown-linux-gnu/lib/

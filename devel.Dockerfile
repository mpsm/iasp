FROM ubuntu:18.04
RUN apt-get update && apt-get install -y curl build-essential libconfig-dev
RUN mkdir /build
WORKDIR /build
RUN curl https://www.openssl.org/source/openssl-1.0.2o.tar.gz | tar zx
RUN cd openssl-1.0.2o && ./config -d && make
RUN ln -s /build/openssl-1.0.2o /build/openssl
WORKDIR /

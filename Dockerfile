FROM ubuntu:latest


ENV CC="musl-gcc -static"
ENV TARGET_PREFIX="/usr/x86_64-linux-musl"
ENV CFLAGS=" -static -I/usr/x86_64-linux-musl/include"
ENV YARA_INCLUDE_DIR="/usr/x86_64-linux-musl/include"
ENV LIBRARY_PATH="/usr/x86_64-linux-musl/lib"
ENV PKG_CONFIG_PATH="/usr/x86_64-linux-musl/lib/pkgconfig"
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="${PATH}:/usr/local/go/bin"

WORKDIR /opt

COPY entrypoint.sh /

RUN apt update && apt install -y automake libtool make gcc libmagic-dev pkg-config flex bison wget musl-tools linux-libc-dev \
    && ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/x86_64-linux-musl/asm \
    && ln -s /usr/include/asm-generic /usr/include/x86_64-linux-musl/asm-generic \
    && ln -s /usr/include/linux /usr/include/x86_64-linux-musl/linux \
    && wget -nv -O openssl.tar.gz https://github.com/openssl/openssl/releases/download/OpenSSL_1_1_1t/openssl-1.1.1t.tar.gz \
    && wget -nv -O yara.tar.gz https://github.com/VirusTotal/yara/archive/v4.3.2.tar.gz \
    && wget -nv -O go-yara.tar.gz https://github.com/hillu/go-yara/archive/refs/tags/v4.3.2.tar.gz \
    && wget -nv -O go.tar.gz https://go.dev/dl/go1.22.2.linux-amd64.tar.gz \
    && tar -xzf go.tar.gz -C /usr/local \
    && mkdir /opt/openssl && tar --strip=1 -xzf openssl.tar.gz -C /opt/openssl \
    && mkdir /opt/yara && tar --strip=1 -xzf yara.tar.gz -C /opt/yara \
    && mkdir /opt/go-yara && tar --strip=1 -xzf go-yara.tar.gz -C /opt/go-yara \
    && rm -rf *.tar.gz \
    && cd openssl && ./config --prefix=$TARGET_PREFIX \
            no-afalgeng \
            no-async \
            no-capieng \
            no-dso \
            no-shared \
            no-sock \
    && make -j 8 && make -j 8 install_sw \
    && cd /opt/yara && ./bootstrap.sh \
    && CFLAGS=$CFLAGS LDFLAGS="$(pkg-config --static --libs libcrypto)" CC=$CC ./configure --with-crypto --disable-shared --prefix=$TARGET_PREFIX \
    && make -j 8 && make -j 8 install \
    && chmod +x /entrypoint.sh

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]

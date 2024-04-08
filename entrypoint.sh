#! /bin/bash

cd /opt/src && go get && \
GOOS=linux GOARCH=amd64 CGO_ENABLED=1 CC=$CC CFLAGS="-I/usr/x86_64-linux-musl/include" PKG_CONFIG_PATH=$PKG_CONFIG_PATH go build -ldflags '-extldflags "-static"' \
-tags yara_static -o yara-scanner && echo "Successfully builded" && cp yara-scanner /opt/vol || echo "failed build"

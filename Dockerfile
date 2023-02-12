FROM nimlang/nim:1.4.8-alpine

RUN apk add --no-cache python3 py3-pip mingw-w64-gcc upx \
&& pip3 install prompt_toolkit requests tabulate jsonc-parser pycryptodome \
&& nimble install -y crc32 nimcrypto pixie wauto winim rc4 https://github.com/itaymigdal/NimProtect

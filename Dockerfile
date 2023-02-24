FROM nimlang/nim:1.4.8

RUN apt update \
&& apt install -y python3 python3-pip mingw-w64 upx \
&& pip3 install prompt_toolkit requests tabulate jsonc-parser pycryptodome \
&& nimble install -y crc32 nimcrypto pixie wauto winim rc4 https://github.com/itaymigdal/NimProtect

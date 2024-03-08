FROM nimlang/nim:1.6.18

RUN apt update \
&& apt install -y python3 python3-pip mingw-w64 upx \
&& pip3 install prompt_toolkit requests tabulate jsonc-parser pycryptodome \
&& nimble install -y nimcrypto crc32 pixie wauto winim rc4 nimprotect
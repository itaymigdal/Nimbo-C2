import nimcrypto
import strutils
import std/[base64, encodings]

proc encrypt_cbc*(plain_text: string, key: string, iv: string): string =    
    var ectx: CBC[aes256]
    var cipher_text_block = newString(aes256.sizeBlock * 2)
    var cipher_text: string
    var plain_text_block: string
    var plain_text_padded = plain_text
    var a = 0
    var b = 31
    
    # padding
    while len(plain_text_padded) mod 32 != 0:
        plain_text_padded = plain_text_padded & " "
    
    # init encryption context
    ectx.init(key, iv)
    
    # encrypt 32-bit blocks
    while b < len(plain_text_padded):
        plain_text_block = plain_text_padded.substr(a, b)
        ectx.encrypt(plain_text_block, cipher_text_block)
        cipher_text.add(cipher_text_block)
        a += 32
        b += 32

    # clear encryption context
    ectx.clear()
    
    return cipher_text


proc decrypt_cbc*(cipher_text: string, key: string, iv: string): string =
    var dctx: CBC[aes256]
    var plain_text_block = newString(aes256.sizeBlock * 2)
    var plain_text: string
    var cipher_text_block: string
    var a = 0
    var b = 31
    
    # init encryption context
    dctx.init(key, iv)

    # decrypt 32-bit blocks
    while b < len(cipher_text):
        cipher_text_block = cipher_text.substr(a, b)
        dctx.decrypt(cipher_text_block, plain_text_block)
        plain_text.add(plain_text_block)
        a += 32
        b += 32
    
    # clear encryption context
    dctx.clear()
    
    # remove padding
    while plain_text.endsWith(" "):
        plain_text.removeSuffix(" ")

    return plain_text


proc encode_64*(text: string,  is_bin: bool = false, encoding: string = "UTF-16"): string =
    var text_to_encode: string
    if is_bin:
        text_to_encode = text
    else:
        text_to_encode = convert(text, encoding, getCurrentEncoding())
    var encoded_text = encode(text_to_encode)
    return encoded_text


proc decode_64*(encoded_text: string, is_bin: bool = false, encoding: string = "UTF-16"): string =
    var text = decode(encoded_text)
    if is_bin:
        return text
    else:
        var right_encoding = convert(text, "UTF-8", encoding)
        return right_encoding

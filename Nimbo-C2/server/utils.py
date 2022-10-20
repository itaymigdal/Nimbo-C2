import os
import base64
from datetime import datetime
from Crypto.Cipher import AES
from jsonc_parser.parser import JsoncParser
from prompt_toolkit import print_formatted_text


def log_message(message, print_time=True):
    if print_time:
        current_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        message = f"[{current_time}] {message}"
    print_formatted_text(message)
    if log_to_file:
        with open(log_file, "a+") as f:
            f.write(f"{message}\n")


def clear_screen():
    if os.name == "nt":
        os.system('cls')
    else:
        os.system('clear')


def sanitize_data(data):
    bad_chars = {
        r"\'": "'"
    }
    for c in bad_chars:
        data = data.replace(c, bad_chars[c])
    return data


def encrypt_cbc(plain_text):
    # pad to *32
    while not (len(plain_text) % 32 == 0):
        plain_text += " "
    # encrypt
    cipher = AES.new(aes_key.encode(), AES.MODE_CBC, aes_iv.encode())
    cipher_text = cipher.encrypt(plain_text.encode())
    return cipher_text


def decrypt_cbc(cipher_text):
    # decrypt
    decipher = AES.new(aes_key.encode(), AES.MODE_CBC, aes_iv.encode())
    plain_text = decipher.decrypt(cipher_text).decode(errors='ignore')
    # remove padding
    while plain_text.endswith(" "):
        plain_text = plain_text[:-1]
    return plain_text


def encode_base_64(text, encoding="utf-16-le"):
    if isinstance(text, str):
        text = text.encode(encoding)
    encoded_text = base64.b64encode(text).decode()
    return encoded_text


def decode_base_64(encoded_text, encoding="utf-16-le"):
    try:  # string
        encoded_text = encoded_text.encode()
        text = base64.b64decode(encoded_text).decode(encoding)
        return text
    except UnicodeDecodeError:  # binary
        bin_text = base64.b64decode(encoded_text)
        return bin_text


def is_valid_file(file_path):
    if not os.path.isfile(file_path):
        print(f"[-] Not a valid file: {file_path}")
        return False
    else:
        return True


def read_file(file_path):
    if not is_valid_file(file_path):
        return False
    try:
        with open(file_path, "rb") as f:
            file_content = f.read()
            return file_content
    except Exception:
        print(f"[-] Could not read file: {file_path}")


def write_file(file_path, file_content):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    try:
        with open(file_path, "wb") as f:
            try:
                f.write(file_content)
            except TypeError:
                f.write(file_content.encode())
            return True
    except Exception as e:
        print(f"[-] Could not write file: {file_path}", e)
        return False


# parse config
config = JsoncParser.parse_file(os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "config.jsonc")))
aes_key = config["communication"]["aes_key"]
aes_iv = config["communication"]["aes_iv"]
log_to_file = config["c2"]["logging"]["log_to_file"]
log_file = config["c2"]["logging"]["log_file"]

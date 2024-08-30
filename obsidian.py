from cryptography.fernet import Fernet
import base64
import hashlib
import itertools
import typing

def encrypt(text: bytes, key: bytes) -> bytes:
    fernet = Fernet(key)
    return fernet.encrypt(text)

def decrypt(text: bytes, key: bytes) -> bytes:
    fernet = Fernet(key)
    return fernet.decrypt(text)

def key_from_password(password: bytes) -> bytes:
    hlib = hashlib.md5()
    hlib.update(password)
    return base64.urlsafe_b64encode(hlib.hexdigest().encode('latin-1'))

def html_to_shard(html: str, shard: str, key: bytes) -> int:
    with open(f"{html}.html", "rb") as html_file:
        encrypted = encrypt(html_file.read(), key)
    with open(f"{shard}.shard", "wb") as shard_file:
        shard_file.write(encrypted)
    return 0

def shard_to_html(html: str, shard: str, key: bytes) -> int:
    with open(f"{shard}.shard", "rb") as shard_file:
        decrypted = decrypt(shard_file.read(), key)
    with open(f"{html}.html", "wb") as html_file:
        html_file.write(decrypted)
    return 0

def break_encryption(text: bytes, mode: typing.Literal["Aa", "0Aa", "%0Aa", "%0Aae", "<%0Aa", "<%0Aae"]) -> bytes:
    charset = []
    if mode == "Aa":
        charset = [chr(i) for i in range(0x41, 0x5A+1)] + [chr(i) for i in range(0x61, 0x7A+1)]
    if mode == "0Aa":
        charset = [chr(i) for i in range(0x30, 0x39+1)] + [chr(i) for i in range(0x41, 0x5A+1)] + [chr(i) for i in range(0x61, 0x7A+1)]
    if mode == "%0Aa":
        charset = [chr(i) for i in range(0x20, 0x7F+1)]
    if mode == "%0Aae":
        charset = [chr(i) for i in range(0x20, 0xFF+1)]
    if mode == "<%0Aa":
        charset = [chr(i) for i in range(0x00, 0x7F+1)]
    if mode == "<%0Aae":
        charset = [chr(i) for i in range(0x00, 0xFF+1)]
    combos = []
    
    for length in range(1, 33):
        for combination in itertools.product(charset, repeat=length):
            combos.append(''.join(combination))
            print(combos[-1])
            if combos[-1] == text:
                return

if __name__ == "__main__":
    break_encryption("GAB", "%0Aa")
    #print(key_from_password(b"greg"))
    #html_to_shard("index", "index", key_from_password(b"greg"))
    #shard_to_html("index", "index", key_from_password(b"greg"))
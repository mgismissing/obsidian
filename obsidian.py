import cryptography.fernet
import base64
import hashlib
import itertools
import typing
import time
import colorama
from colorama import Fore, Back, Style
colorama.init(autoreset=True)

def encrypt(text: bytes, key: bytes) -> bytes:
    fernet = cryptography.fernet.Fernet(key)
    return fernet.encrypt(text)

def decrypt(text: bytes, key: bytes) -> bytes:
    fernet = cryptography.fernet.Fernet(key)
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

def break_encryption_shard_to_html(html: str, shard: str, mode: typing.Literal["A", "a", "Aa", "0Aa", "%0Aa", "%0Aae", "<%0Aa", "<%0Aae"], verbose: bool = False, max_length: int = 8) -> int:
    with open(f"{shard}.shard", "rb") as shard_file:
        decrypted = break_encryption(shard_file.read(), mode, verbose, max_length)
    with open(f"{html}.html", "wb") as html_file:
        html_file.write(decrypted)
    return 0

def break_encryption_smart_shard_to_html(html: str, shard: str, verbose: bool = False, max_length: int = 32) -> int:
    with open(f"{shard}.shard", "rb") as shard_file:
        decrypted = break_encryption_smart(shard_file.read(), verbose, max_length)
        if decrypted == None:
            return 1
    with open(f"{html}.html", "wb") as html_file:
        html_file.write(decrypted)
    return 0

def break_encryption(text: bytes, mode: typing.Literal["A", "a", "Aa", "0Aa", "%0Aa", "%0Aae", "<%0Aa", "<%0Aae"], verbose: bool = False, max_length: int = 8, min_length: int = 1) -> bytes:
    charset = []
    if mode == "A":
        charset = [chr(i) for i in range(0x41, 0x5A+1)]
    if mode == "a":
        charset = [chr(i) for i in range(0x61, 0x7A+1)]
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
    
    if charset == []:
        raise ValueError("the current mode is not valid")
    
    if verbose: print(f"Decrypting text with mode \"{mode}\"...")
    
    for length in range(min_length, max_length+1):
        for combination in itertools.product(charset, repeat=length):
            combo = ''.join(combination)
            if verbose: print(f"\rTrying {combo.rjust(max_length, "_")}: ", end="")
            try:
                decrypted = decrypt(text, key_from_password(bytes(combo, "utf-8")))
                if verbose: print(f"{colorama.Fore.LIGHTGREEN_EX}Match!      ", end="\n")
                return decrypted
            except cryptography.fernet.InvalidToken:
                if verbose: print(f"{colorama.Fore.LIGHTRED_EX}No match", end="\r")
    print(end="\n")
    return None

def break_encryption_smart(text: bytes, verbose: bool = False, max_length: int = 32) -> bytes:
    for i in range(1, max_length+1):
        decrypted = break_encryption(text, "A", verbose, i, i-1)
        if decrypted != None: return decrypted
        decrypted = break_encryption(text, "a", verbose, i, i-1)
        if decrypted != None: return decrypted
        decrypted = break_encryption(text, "Aa", verbose, i, i-1)
        if decrypted != None: return decrypted
        decrypted = break_encryption(text, "0Aa", verbose, i, i-1)
        if decrypted != None: return decrypted
        decrypted = break_encryption(text, "%0Aa", verbose, i, i-1)
        if decrypted != None: return decrypted
        decrypted = break_encryption(text, "%0Aae", verbose, i, i-1)
        if decrypted != None: return decrypted
        decrypted = break_encryption(text, "<%0Aa", verbose, i, i-1)
        if decrypted != None: return decrypted
        decrypted = break_encryption(text, "<%0Aae", verbose, i, i-1)
        if decrypted != None: return decrypted
    return None
#!/usr/bin/env python3
"""
Provides a number of encoders, decoders, encryptors and decryptors.

Created By r2dr0dn.
Improvements by Haxys.
Updated 2019.12.04.
"""

import base64
import binascii
import binhex
import os
import string
import sys

try:
    from colorama import Fore, Style, init
    from Crypto.Cipher import AES
    from Crypto.Random import random
    from cryptography.fernet import Fernet
except ImportError:
    print(
        "ERROR: Missing required libraries.\n"
        "Install dependencies with: pip install -r requirements.txt"
    )
    sys.exit(1)


init()
print(
    f"""{Fore.MAGENTA}
https://github.com/r2dr0dn
{Fore.CYAN}
 ####   #####   #   #  #####   #####  ######
#    #  #    #   # #   #    #    #        #
#       #    #    #    #    #    #       #
#       #####     #    #####     #      #
#    #  #   #     #    #         #     #
 ####   #    #    #    #         #    ######  {Fore.RED}v5.0{Style.RESET_ALL}

{Fore.CYAN}Created by: {Fore.RED}r2dr0dn
{Fore.YELLOW}Improved by: {Fore.RED}Haxys{Style.RESET_ALL}
"""
)

# Global Variables
MENU_OPTIONS = list()


def get(datatype):
    """Request data with a prompt."""
    try:
        (color, message) = {
            "plaintext": (Fore.GREEN, "Enter plaintext message"),
            "encoded": (Fore.YELLOW, "Enter encoded message"),
            "encrypted": (Fore.YELLOW, "Enter encrypted message"),
            "filename": (Fore.MAGENTA, "Specify filename"),
            "password": (Fore.RED, "Enter encryption password"),
        }[datatype]
    except KeyError:
        color = Fore.CYAN
        message = datatype
    return input(f"{color}{message}: {Style.RESET_ALL}").encode()


def show(datatype, output):
    """Reveal data with a prompt."""
    try:
        (color, message) = {
            "filename": (Fore.MAGENTA, "Output saved as"),
            "encoded": (Fore.YELLOW, "Encoded message"),
            "encrypted": (Fore.YELLOW, "Encrypted message"),
            "plaintext": (Fore.GREEN, "Plaintext"),
            "password": (Fore.RED, "Encryption password"),
        }[datatype]
    except KeyError:
        color = Fore.CYAN
        message = datatype
    print(f"{color}{message}:{Style.RESET_ALL}\n{output}")


def random_key(length):
    """Generate a random key of the specified length."""
    chars = string.ascii_letters + string.digits
    keypass = "".join(random.choice(chars) for x in range(length))
    return keypass


def hex_enc():
    """Encode to Hexadecimal."""
    plaintext = get("plaintext")
    output = binascii.hexlify(plaintext).decode()
    show("encoded", output)


MENU_OPTIONS.append(hex_enc)


def hex_dec():
    """Decode from Hexadecimal."""
    encoded_message = get("encoded")
    output = binascii.unhexlify(encoded_message).decode()
    show("plaintext", output)


MENU_OPTIONS.append(hex_dec)


def uu_enc():
    """Encode with uuencode."""
    plaintext = get("plaintext")
    output = binascii.b2a_uu(plaintext).decode()
    show("encoded", output)


MENU_OPTIONS.append(uu_enc)


def uu_dec():
    """Decode with uudecode."""
    encoded_message = get("encoded")
    output = binascii.a2b_uu(encoded_message).decode()
    show("plaintext", output)


MENU_OPTIONS.append(uu_dec)


def base64_enc():
    """Encode with Base64."""
    plaintext = get("plaintext")
    output = base64.b64encode(plaintext).decode()
    show("encoded", output)


MENU_OPTIONS.append(base64_enc)


def base64_dec():
    """Decode with Base64."""
    encoded_message = get("encoded")
    output = base64.b64decode(encoded_message).decode()
    show("plaintext", output)


MENU_OPTIONS.append(base64_dec)


def binhex_enc():
    """Encode with BinHex4."""
    temp_filename = f"temp_{random_key(32)}"
    with open(temp_filename, "wb") as outfile:
        outfile.write(get("plaintext"))
    dest_filename = get("filename").decode()
    binhex.binhex(temp_filename, dest_filename)
    os.unlink(temp_filename)
    show("outfile", dest_filename)


MENU_OPTIONS.append(binhex_enc)


def binhex_dec():
    """Decode with BinHex4."""
    temp_filename = f"temp_{random_key(32)}"
    binhex.hexbin(get("filename").decode(), temp_filename)
    with open(temp_filename, "rb") as infile:
        show("plaintext", infile.read().decode())
    os.unlink(temp_filename)


MENU_OPTIONS.append(binhex_dec)


def fernet_enc():
    """Encrypt with Fernet (Symmetric)."""
    plaintext = get("plaintext")
    encryption_key = Fernet.generate_key()
    instance = Fernet(encryption_key)
    output = instance.encrypt(plaintext).decode()
    show("password", encryption_key.decode())
    show("encrypted", output)


MENU_OPTIONS.append(fernet_enc)


def fernet_dec():
    """Decrypt with Fernet (Symmetric)."""
    encrypted_text = get("encrypted")
    password = get("password")
    instance = Fernet(password)
    decrypted_text = instance.decrypt(encrypted_text).decode()
    show("plaintext", decrypted_text)


MENU_OPTIONS.append(fernet_dec)


def aes_enc_auto():
    """Encrypt with AES."""
    keypass = random_key(16)
    data = get("plaintext")
    filename = get("filename").decode()
    cipher = AES.new(keypass.encode(), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    with open(filename, "wb") as outfile:
        _ = [outfile.write(item) for item in (cipher.nonce, tag, ciphertext)]
    show("password", keypass)
    show("filename", filename)


MENU_OPTIONS.append(aes_enc_auto)


def aes_dec_auto():
    """Decrypt with AES."""
    filename = get("filename")
    keypass = get("password")
    with open(filename, "rb") as infile:
        nonce, tag, ciphertext = [infile.read(x) for x in (16, 16, -1)]
    cipher = AES.new(keypass, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag).decode()
    show("plaintext", data)


MENU_OPTIONS.append(aes_dec_auto)


# Main Function
def main():
    """Present the user with the main menu when the script is run directly."""
    try:
        while True:
            print(
                "\n"
                + Fore.CYAN
                + "Choose from the following options, or press Ctrl-C to quit:"
                + Style.RESET_ALL
            )
            for index, option in enumerate(MENU_OPTIONS, 1):
                print(f"{index}. {' ' if index < 10 else ''}"
                      f"{option.__doc__}")
            choice = get("Selection")
            print()
            try:
                MENU_OPTIONS[int(choice) - 1]()
            except IndexError:
                print(Fore.RED + "Unknown option." + Style.RESET_ALL)
            except ValueError:
                print(
                    f"{Fore.RED}Invalid option."
                    + "Enter the number of your selection."
                    + Style.RESET_ALL
                )
    except KeyboardInterrupt:
        print(
            f"\n{Fore.RED}Program terminated. "
            f"{Fore.WHITE}{Style.BRIGHT}Have a nice day!"
            f"{Style.RESET_ALL}"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()

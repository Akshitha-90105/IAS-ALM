
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# AES-256 encryption key (32 bytes)
KEY = b"ALM2_AES_DEMO_KEY_12345678901234"


def encrypt_data(plaintext):
    # Generate a random Initialization Vector
    iv = get_random_bytes(AES.block_size)

    cipher = AES.new(KEY, AES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(
        pad(plaintext, AES.block_size)
    )

    return iv, ciphertext


def decrypt_data(iv, ciphertext):
    cipher = AES.new(KEY, AES.MODE_CBC, iv)

    plaintext = unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    )

    return plaintext

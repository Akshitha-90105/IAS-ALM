
from sdes import encrypt_byte, decrypt_byte, encrypt_data, decrypt_data

KEY = 0b1010000010

message = b"HELLO"

ciphertext = encrypt_data(message, KEY)

decrypted = decrypt_data(ciphertext, KEY)

print("Original message:", message)
print("Encrypted bytes:", ciphertext)
print("Ciphertext preview:", ciphertext.hex())
print("Decrypted message:", decrypted)

if decrypted == message:
    print("SDES encryption and decryption successful!")
else:
    print("Error in SDES!")

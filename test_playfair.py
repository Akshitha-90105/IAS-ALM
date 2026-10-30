from playfair import encrypt, decrypt

key = "MONARCHY"
message = "HELLO"

cipher = encrypt(message, key)

print("Plaintext:", message)
print("Ciphertext:", cipher)
print("Decrypted:", decrypt(cipher, key))
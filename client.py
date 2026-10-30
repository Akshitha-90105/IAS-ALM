import socket
import json
import base64
import hashlib
from pathlib import Path

from caesar import encrypt as caesar_encrypt, decrypt as caesar_decrypt
from playfair import encrypt as playfair_encrypt, decrypt as playfair_decrypt
from sdes import encrypt_data, decrypt_data

HOST = '127.0.0.1'
PORT = 55555

CAESAR_KEY = 3
PLAYFAIR_KEY = "MONARCHY"
SDES_KEY = 0b1010000010

CLIENT_FILE = Path("client_files/sample_1MB.bin")
RECEIVED_FOLDER = Path("received_files")
RECEIVED_FOLDER.mkdir(exist_ok=True)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

print("Connected to server!")

reader = client.makefile('r', encoding='utf-8')
writer = client.makefile('w', encoding='utf-8')


while True:

    print("\n========== ALGORITHM MENU ==========")
    print("1. Caesar Cipher")
    print("2. Playfair Cipher")
    print("3. SDES")
    print("4. SDES File Transfer (1 MB and 10 KB)")
    print("5. Exit")

    choice = input("Select option: ")

    if choice == '5':
        writer.write(json.dumps({"type": "exit"}) + "\n")
        writer.flush()
        break

    elif choice == '4':

        print("\n========== CLIENT FILE TRANSFER ==========")

        if not CLIENT_FILE.exists():
            print("Client test file not found:", CLIENT_FILE)
            continue

        original_bytes = CLIENT_FILE.read_bytes()
        encrypted_bytes = encrypt_data(original_bytes, SDES_KEY)

        print("Original file:", CLIENT_FILE.name)
        print("Original file size:", len(original_bytes), "bytes")
        print("Encrypted ciphertext preview:", encrypted_bytes[:32].hex())
        print("Plaintext preview:", original_bytes[:32].hex())

        upload_data = {
            "type": "file_upload",
            "filename": CLIENT_FILE.name,
            "size": len(original_bytes),
            "ciphertext": base64.b64encode(encrypted_bytes).decode("ascii"),
            "sha256": sha256(original_bytes)
        }

        writer.write(json.dumps(upload_data) + "\n")
        writer.flush()

        print("\nEncrypted 1 MB file sent to server.")

        # Receive the server's 10 KB file
        response_line = reader.readline()

        if not response_line:
            print("Server disconnected.")
            break

        response = json.loads(response_line)

        if response["type"] == "error":
            print("Server error:", response["message"])
            continue

        if response["type"] != "file_download":
            print("Unexpected server response.")
            continue

        print("\n========== SERVER FILE RECEIVED ==========")

        filename = Path(response["filename"]).name

        encrypted_bytes = base64.b64decode(response["ciphertext"])
        decrypted_bytes = decrypt_data(encrypted_bytes, SDES_KEY)

        output_path = RECEIVED_FOLDER / ("from_server_" + filename)
        output_path.write_bytes(decrypted_bytes)

        print("Filename:", filename)
        print("Encrypted file size:", len(encrypted_bytes), "bytes")
        print("Ciphertext preview:", encrypted_bytes[:32].hex())
        print("Decrypted plaintext preview:", decrypted_bytes[:32].hex())
        print("Decrypted file saved:", output_path)

        valid = (
            len(decrypted_bytes) == response["size"]
            and sha256(decrypted_bytes) == response["sha256"]
        )

        print("File integrity:", "SUCCESS" if valid else "FAILED")

        continue

    elif choice == '1':
        algorithm = "Caesar"

    elif choice == '2':
        algorithm = "Playfair"

    elif choice == '3':
        algorithm = "SDES"

    else:
        print("Invalid choice! Try again.")
        continue

    message = input("Enter plaintext message: ")

    if algorithm == "Caesar":
        ciphertext = caesar_encrypt(message, CAESAR_KEY)

    elif algorithm == "Playfair":
        ciphertext = playfair_encrypt(message, PLAYFAIR_KEY)

    else:
        encrypted_bytes = encrypt_data(message.encode("utf-8"), SDES_KEY)
        ciphertext = encrypted_bytes.hex()

    print("\n========== CLIENT ENCRYPTION ==========")
    print("Original Plaintext:", message)
    print("Encrypted Ciphertext:", ciphertext)

    data = {
        "type": "message",
        "algorithm": algorithm,
        "ciphertext": ciphertext
    }

    writer.write(json.dumps(data) + "\n")
    writer.flush()

    response_line = reader.readline()

    if not response_line:
        print("Server disconnected.")
        break

    response = json.loads(response_line)

    received_ciphertext = response["ciphertext"]
    received_algorithm = response["algorithm"]

    print("\n========== SERVER MESSAGE ==========")
    print("Received Ciphertext:", received_ciphertext)

    if received_algorithm == "Caesar":
        plaintext = caesar_decrypt(received_ciphertext, CAESAR_KEY)

    elif received_algorithm == "Playfair":
        plaintext = playfair_decrypt(received_ciphertext, PLAYFAIR_KEY)

    else:
        encrypted_bytes = bytes.fromhex(received_ciphertext)
        plaintext = decrypt_data(encrypted_bytes, SDES_KEY).decode("utf-8")

    print("Decrypted Plaintext:", plaintext)


reader.close()
writer.close()
client.close()

print("Client stopped.")
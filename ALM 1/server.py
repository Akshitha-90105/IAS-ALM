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

SERVER_FILE = Path("server_files/sample_10KB.bin")
RECEIVED_FOLDER = Path("received_files")
RECEIVED_FOLDER.mkdir(exist_ok=True)


def decrypt_message(algorithm, ciphertext):
    if algorithm == "Caesar":
        return caesar_decrypt(ciphertext, CAESAR_KEY)

    elif algorithm == "Playfair":
        return playfair_decrypt(ciphertext, PLAYFAIR_KEY)

    elif algorithm == "SDES":
        encrypted_bytes = bytes.fromhex(ciphertext)
        return decrypt_data(encrypted_bytes, SDES_KEY).decode("utf-8")


def encrypt_message(algorithm, plaintext):
    if algorithm == "Caesar":
        return caesar_encrypt(plaintext, CAESAR_KEY)

    elif algorithm == "Playfair":
        return playfair_encrypt(plaintext, PLAYFAIR_KEY)

    elif algorithm == "SDES":
        encrypted_bytes = encrypt_data(plaintext.encode("utf-8"), SDES_KEY)
        return encrypted_bytes.hex()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(1)

print("Server started...")
print("Waiting for client connection...")

conn, addr = server.accept()
print("Connected to:", addr)

reader = conn.makefile('r', encoding='utf-8')
writer = conn.makefile('w', encoding='utf-8')


while True:
    line = reader.readline()

    if not line:
        break

    data = json.loads(line)

    if data["type"] == "exit":
        print("Client disconnected.")
        break

    # Receive the 1 MB file from the client
    elif data["type"] == "file_upload":

        print("\n========== CLIENT FILE RECEIVED ==========")

        filename = Path(data["filename"]).name
        encrypted_bytes = base64.b64decode(data["ciphertext"])
        decrypted_bytes = decrypt_data(encrypted_bytes, SDES_KEY)

        output_path = RECEIVED_FOLDER / ("from_client_" + filename)
        output_path.write_bytes(decrypted_bytes)

        print("Filename:", filename)
        print("Encrypted file size:", len(encrypted_bytes), "bytes")
        print("Ciphertext preview:", encrypted_bytes[:32].hex())
        print("Decrypted plaintext preview:", decrypted_bytes[:32].hex())
        print("Decrypted file saved:", output_path)

        valid = (
            len(decrypted_bytes) == data["size"]
            and sha256(decrypted_bytes) == data["sha256"]
        )

        print("File integrity:", "SUCCESS" if valid else "FAILED")

        # Send the 10 KB file from server to client
        print("\n========== SENDING SERVER FILE ==========")

        if not SERVER_FILE.exists():
            print("Server file not found:", SERVER_FILE)
            writer.write(json.dumps({
                "type": "error",
                "message": "Server test file not found."
            }) + "\n")
            writer.flush()
            continue

        original_bytes = SERVER_FILE.read_bytes()
        encrypted_bytes = encrypt_data(original_bytes, SDES_KEY)

        print("Original file:", SERVER_FILE.name)
        print("Original file size:", len(original_bytes), "bytes")
        print("Encrypted ciphertext preview:", encrypted_bytes[:32].hex())
        print("Plaintext preview:", original_bytes[:32].hex())

        response = {
            "type": "file_download",
            "filename": SERVER_FILE.name,
            "size": len(original_bytes),
            "ciphertext": base64.b64encode(encrypted_bytes).decode("ascii"),
            "sha256": sha256(original_bytes)
        }

        writer.write(json.dumps(response) + "\n")
        writer.flush()

        print("Encrypted file sent to client successfully.")

    # Normal encrypted text communication
    elif data["type"] == "message":

        algorithm = data["algorithm"]
        ciphertext = data["ciphertext"]

        print("\n========== CLIENT MESSAGE ==========")
        print("Selected Algorithm:", algorithm)
        print("Received Ciphertext:", ciphertext)

        plaintext = decrypt_message(algorithm, ciphertext)
        print("Decrypted Plaintext:", plaintext)

        reply = input("\nEnter message to send to client: ")

        encrypted_reply = encrypt_message(algorithm, reply)

        print("\n========== SERVER MESSAGE ==========")
        print("Original Plaintext:", reply)
        print("Encrypted Ciphertext:", encrypted_reply)

        response = {
            "type": "message",
            "algorithm": algorithm,
            "ciphertext": encrypted_reply
        }

        writer.write(json.dumps(response) + "\n")
        writer.flush()


reader.close()
writer.close()
conn.close()
server.close()

print("Server stopped.")

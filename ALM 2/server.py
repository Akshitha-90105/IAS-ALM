
import socket
import json
import base64
from pathlib import Path

from aes import encrypt_data, decrypt_data

HOST = "127.0.0.1"
PORT = 55555

SERVER_FILE = Path(__file__).parent / "server_files" / "server_5kb.txt"


def display_data(title, plaintext, ciphertext):
    print(f"\n===== {title} =====")

    print("\nPlaintext:")
    print(plaintext.decode("utf-8"))

    print("\nCiphertext (Base64):")
    print(base64.b64encode(ciphertext).decode("ascii"))


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)

        print(f"AES Server listening on {HOST}:{PORT}")
        print("Waiting for client...")

        connection, address = server.accept()

        with connection:
            print(f"\nConnected to client: {address}")

            stream = connection.makefile("rwb")

            # Receive encrypted file from client
            request = json.loads(stream.readline().decode("utf-8"))

            client_name = request["filename"]
            client_iv = base64.b64decode(request["iv"])
            client_ciphertext = base64.b64decode(request["ciphertext"])

            client_plaintext = decrypt_data(
                client_iv, client_ciphertext
            )

            print(f"\nReceived file: {client_name}")
            display_data(
                "CLIENT TO SERVER",
                client_plaintext,
                client_ciphertext
            )

            # Read and encrypt server's 5 KB file
            server_plaintext = SERVER_FILE.read_bytes()

            server_iv, server_ciphertext = encrypt_data(server_plaintext)

            display_data(
                "SERVER TO CLIENT",
                server_plaintext,
                server_ciphertext
            )

            # Send encrypted file to client
            response = {
                "filename": SERVER_FILE.name,
                "iv": base64.b64encode(server_iv).decode("ascii"),
                "ciphertext": base64.b64encode(
                    server_ciphertext
                ).decode("ascii")
            }

            stream.write((json.dumps(response) + "\n").encode("utf-8"))
            stream.flush()

            print("\n5 KB encrypted file sent successfully!")

            stream.close()


if __name__ == "__main__":
    main()

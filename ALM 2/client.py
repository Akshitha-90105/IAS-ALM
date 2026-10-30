
import socket
import json
import base64
from pathlib import Path

from aes import encrypt_data, decrypt_data

HOST = "127.0.0.1"
PORT = 55555

CLIENT_FILE = Path(__file__).parent / "client_files" / "client_10kb.txt"


def display_data(title, plaintext, ciphertext):
    print(f"\n===== {title} =====")

    print("\nPlaintext:")
    print(plaintext.decode("utf-8"))

    print("\nCiphertext (Base64):")
    print(base64.b64encode(ciphertext).decode("ascii"))


def main():
    # Read client's 10 KB text file
    client_plaintext = CLIENT_FILE.read_bytes()

    print(f"File selected: {CLIENT_FILE.name}")
    print(f"File size: {len(client_plaintext)} bytes")

    # Encrypt client file
    client_iv, client_ciphertext = encrypt_data(client_plaintext)

    display_data(
        "CLIENT TO SERVER",
        client_plaintext,
        client_ciphertext
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((HOST, PORT))

        stream = client.makefile("rwb")

        # Send encrypted file to server
        request = {
            "filename": CLIENT_FILE.name,
            "iv": base64.b64encode(client_iv).decode("ascii"),
            "ciphertext": base64.b64encode(
                client_ciphertext
            ).decode("ascii")
        }

        stream.write((json.dumps(request) + "\n").encode("utf-8"))
        stream.flush()

        print("\n10 KB encrypted file sent to server!")

        # Receive server's encrypted file
        response = json.loads(stream.readline().decode("utf-8"))

        server_name = response["filename"]
        server_iv = base64.b64decode(response["iv"])
        server_ciphertext = base64.b64decode(response["ciphertext"])

        # Decrypt server file
        server_plaintext = decrypt_data(
            server_iv, server_ciphertext
        )

        print(f"\nReceived file: {server_name}")

        display_data(
            "SERVER TO CLIENT",
            server_plaintext,
            server_ciphertext
        )

        # Save decrypted file
        output_folder = Path(__file__).parent / "received_files"
        output_folder.mkdir(exist_ok=True)

        output_file = output_folder / server_name
        output_file.write_bytes(server_plaintext)

        print(f"\nDecrypted file saved to: {output_file}")
        print("\nAES file transfer completed successfully!")

        stream.close()


if __name__ == "__main__":
    main()

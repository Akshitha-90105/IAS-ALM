
from pathlib import Path

def create_text_file(path, size, paragraph):
    text = paragraph

    while len(text.encode("utf-8")) < size:
        text += paragraph

    content = text.encode("utf-8")[:size]
    Path(path).write_bytes(content)

    print(f"Created {path}: {len(content)} bytes")


client_text = (
    "This is the ALM 2 client to server AES file transfer demonstration. "
    "The client encrypts this readable message using AES before sending it "
    "through the TCP connection. The server receives the encrypted data, "
    "decrypts it, and verifies the original message. "
)

server_text = (
    "This is the ALM 2 server to client AES file transfer demonstration. "
    "The server encrypts this separate readable message using AES and sends "
    "it to the client. The client decrypts the received data and checks "
    "that the original message has been recovered. "
)

create_text_file("client_files/client_10kb.txt", 10 * 1024, client_text)
create_text_file("server_files/server_5kb.txt", 5 * 1024, server_text)

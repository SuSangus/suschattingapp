import socket
import threading
import time
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

def demonstration_mode():
    return input("Enter 'demo' to start in demonstration mode, or press Enter to continue: ").lower() == 'demo'

def generate_ecdh_key_and_aes_key(client_socket, demo):
    ecdh_key = ECC.generate(curve='P-256')
    if demo:
        print(f"Generated ECDH key: {ecdh_key.export_key(format='PEM')}")
    client_socket.send(ecdh_key.public_key().export_key(format='PEM'))

    peer_pubkey_pem = client_socket.recv(2048).decode()
    if demo:
        print(f"Received peer's public ECDH key: {peer_pubkey_pem}")
    peer_pubkey = ECC.import_key(peer_pubkey_pem)

    shared_key = ecdh_key.d * peer_pubkey.pointQ
    aes_key = HKDF(shared_key.xy[0].to_bytes() + shared_key.xy[1].to_bytes(), 16, b'', SHA256)
    if demo:
        print(f"Derived AES key: {aes_key.hex()}")
    return aes_key

def encrypt_and_send(message, aes_key, client_socket, demo):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.iv + cipher.encrypt(pad(message.encode(), AES.block_size))
    if demo:
        print(f"Encrypted message: {ct_bytes.hex()}")
    client_socket.sendall(ct_bytes)

def receive_and_decrypt(client_socket, aes_key, demo):
    ct = client_socket.recv(1024)
    if ct:
        iv = ct[:16]
        ct = ct[16:]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        if demo:
            print(f"Received encrypted message: {ct.hex()}")
            print(f"Decrypted message: {pt.decode()}")
        else:
            print(f"Peer says: {pt.decode()}")

def handle_incoming_messages(client_socket, aes_key, demo):
    while True:
        receive_and_decrypt(client_socket, aes_key, demo)

def accept_connections(server_socket, demo):
    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection established with {addr}")
        aes_key = generate_ecdh_key_and_aes_key(client_socket, demo)
        threading.Thread(target=handle_incoming_messages, args=(client_socket, aes_key, demo)).start()

def connect_to_peer(demo):
    print("Which Raspberry Pi do you want to connect to?")
    pi_number = input("Enter a number (1-4): ")
    peer_ip = f"192.168.1.{pi_number}"
    peer_port = 12345

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((peer_ip, peer_port))
        print(f"Connected to Raspberry Pi at {peer_ip}:{peer_port}")

        aes_key = generate_ecdh_key_and_aes_key(client_socket, demo)
        threading.Thread(target=handle_incoming_messages, args=(client_socket, aes_key, demo)).start()

        while True:
            msg = input("Enter your message: ")
            if msg.lower() == 'exit':
                break
            encrypt_and_send(msg, aes_key, client_socket, demo)

        client_socket.close()
        print("Disconnected. Going back to connect screen.")
    except Exception as e:
        print(f"Connection failed: {e}")

def start_server(demo):
    server_ip = '0.0.0.0'
    server_port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((server_ip, server_port))
    server_socket.listen()

    threading.Thread(target=accept_connections, args=(server_socket, demo)).start()

def main():
    demo = demonstration_mode()
    start_server(demo)
    time.sleep(1)
    while True:
        connect_to_peer(demo)


if __name__ == "__main__":
    main()

import socket
import ssl
import pickle
from threading import Thread
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from ecdh import generate_keypair, compute_shared_secret
from globalfunc import GlobalFunc

class VPNServer:
    def __init__(self, port, certfile, keyfile):
        self.port = port
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('0.0.0.0', self.port))
        self.server_socket.listen(3)
        print(f"VPN Server is listening on port {self.port}")

    def handle_client(self, client_connection):
        try:
            secure_socket = self.context.wrap_socket(client_connection, server_side=True)
            print("Established secure connection with client")

            #ECDH key exchange
            server_private_key, server_public_key = generate_keypair()
            secure_socket.sendall(pickle.dumps(server_public_key))
            print("Sent server's public key")

            client_public_key = pickle.loads(secure_socket.recv(4096))
            print("Received client's public key")

            shared_secret = compute_shared_secret(server_private_key, client_public_key)
            symmetric_key = sha256(str(shared_secret).encode()).digest()
            print("Derived symmetric key")

            self.process_messages(secure_socket, symmetric_key)
        except Exception as e:
            print(f"Error with client connection: {e}")

    def process_messages(self, secure_socket, symmetric_key):
        try:
            while True:
                encrypted_data = secure_socket.recv(4096)
                if not encrypted_data:
                    break
                decrypted_message = GlobalFunc.decrypt_message(encrypted_data, symmetric_key)
                print(f"Received from client: {decrypted_message.decode()}")

                response = f"Server response: {decrypted_message.decode()}"
                encrypted_response = GlobalFunc.encrypt_message(response.encode(), symmetric_key)
                secure_socket.sendall(encrypted_response)
        except Exception as e:
            print(f"Error processing messages: {e}")
        finally:
            secure_socket.close()

    def run(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Accepted connection from {addr}")
            client_thread = Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()

def main():
    vpn_server = VPNServer(port=50001, certfile="ActuallyVPN\server.crt", keyfile="ActuallyVPN\server.key")
    vpn_server.run()

if __name__ == "__main__":
    main()

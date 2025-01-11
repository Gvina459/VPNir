import socket
import ssl
import pickle
from users import User
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from ecdh import generate_keypair, compute_shared_secret
from globalfunc import GlobalFunc

class VPNClient:
    def __init__(self, server_addr, server_port, cafile):
        self.server_addr = server_addr
        self.server_port = server_port
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations(cafile=cafile)
        self.context.check_hostname = False
        self.symmetric_key = None

    def connect(self, username, password):
        self.username = username
        self.password = password
        user = User(self.username, self.password)

        if not user.verify_user():
            print("Authentication failed")
            return

        private_key, client_public_key = generate_keypair()

        try:
            print("Connecting to VPN server with TLS/SSL")
            with socket.create_connection((self.server_addr, self.server_port)) as raw_socket:
                with self.context.wrap_socket(raw_socket, server_hostname=self.server_addr) as secure_socket:
                    print("Secure connection established")

                    #ECDH key exchange
                    secure_socket.sendall(pickle.dumps(client_public_key))
                    print("Sent client public key")

                    server_public_key_data = secure_socket.recv(4096)
                    server_public_key = pickle.loads(server_public_key_data)
                    print("Received server public key")

                    shared_secret = compute_shared_secret(private_key, server_public_key)
                    self.symmetric_key = sha256(str(shared_secret).encode()).digest()
                    print(self.symmetric_key)
                    print("Derived symmetric key")

                    self.process_messages(secure_socket)
        except Exception as e:
            print(f"Error connecting to server: {e}")

    def process_messages(self, secure_socket):
        try:
            while True:
                message = input("Enter a message to send: ")
                if message.lower() == "exit":
                    break

                encrypted_message = GlobalFunc.encrypt_message(message.encode(), self.symmetric_key)
                secure_socket.sendall(encrypted_message)
                print("Sent encrypted message to server")

                encrypted_response = secure_socket.recv(4096)
                if not encrypted_response:
                    print("No response from server. Closing connection.")
                    break

                decrypted_response = GlobalFunc.decrypt_message(encrypted_response, self.symmetric_key)
                print(f"Received from server: {decrypted_response.decode()}")
        except Exception as e:
            print(f"Error processing messages: {e}")
        finally:
            secure_socket.close()

if __name__ == "__main__":
    vpn_client = VPNClient("localhost", 50001, cafile="ActuallyVPN\server.crt")
    vpn_client.connect("testuser", "mypassword123")

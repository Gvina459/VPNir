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
        self.secure_socket = None
    
    def connect_otp(self, email):
        """Connect using OTP authentication (no password needed)"""
        user = User(email, "")

        private_key, client_public_key = generate_keypair()

        try:
            print("Connecting to VPN server with TLS/SSL")
            raw_socket = socket.create_connection((self.server_addr, self.server_port))
            self.secure_socket = self.context.wrap_socket(raw_socket, server_hostname=self.server_addr)
            print("Secure connection established")

            server_public_key_data = self.secure_socket.recv(4096)
            server_public_key = pickle.loads(server_public_key_data)
            print("Received server public key")

            self.secure_socket.sendall(pickle.dumps(client_public_key))
            print("Sent client public key")

            shared_secret = compute_shared_secret(private_key, server_public_key)
            self.symmetric_key = sha256(str(shared_secret).encode()).digest()
            print("Derived symmetric key")

        except Exception as e:
            print(f"Error connecting to server: {e}")
            self.secure_socket = None


    def connect(self, email, password):
        self.email = email
        self.password = password
        user = User(self.email, self.password)

        if not user.verify_user():
            print("Authentication failed")
            return

        private_key, client_public_key = generate_keypair()

        try:
            print("Connecting to VPN server with TLS/SSL")
            raw_socket = socket.create_connection((self.server_addr, self.server_port))
            self.secure_socket = self.context.wrap_socket(raw_socket, server_hostname=self.server_addr)
            print("Secure connection established")

            # **ECDH Key Exchange**
            self.secure_socket.sendall(pickle.dumps(client_public_key))
            print("Sent client public key")

            server_public_key_data = self.secure_socket.recv(4096)
            server_public_key = pickle.loads(server_public_key_data)
            print("Received server public key")

            shared_secret = compute_shared_secret(private_key, server_public_key)
            self.symmetric_key = sha256(str(shared_secret).encode()).digest()
            print("Derived symmetric key")

        except Exception as e:
            print(f"Error connecting to server: {e}")
            self.secure_socket = None  # Reset on failure

    def disconnect(self):
        if self.secure_socket:
            try:
                self.secure_socket.close()
                print("Disconnected from VPN server.")
            except Exception as e:
                print(f"Error disconnecting: {e}")
            finally:
                self.secure_socket = None

    def process_messages(self):
        if not self.secure_socket:
            print("Error: No secure connection established.")
            return
        
        try:
            while True:
                message = input("Enter a message to send: ")
                if message.lower() == "exit":
                    break

                if not self.symmetric_key:
                    print("Error: No encryption key established.")
                    break

                encrypted_message = GlobalFunc.encrypt_message(message.encode(), self.symmetric_key)
                self.secure_socket.sendall(encrypted_message)
                print("Sent encrypted message to server")

                encrypted_response = self.secure_socket.recv(4096)
                if not encrypted_response:
                    print("No response from server. Closing connection.")
                    break

                decrypted_response = GlobalFunc.decrypt_message(encrypted_response, self.symmetric_key)
                print(f"Received from server: {decrypted_response.decode()}")

        except Exception as e:
            print(f"Error processing messages: {e}")
        finally:
            if self.secure_socket:
                self.secure_socket.close()
                self.secure_socket = None  # Reset socket

# Uncomment to test
# if __name__ == "__main__":
#     vpn_client = VPNClient("localhost", 50001, cafile="ActuallyVPN/server.crt")
#     vpn_client.connect("testuser@example.com", "mypassword123")
#     vpn_client.process_messages()

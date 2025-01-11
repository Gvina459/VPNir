import subprocess
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class GlobalFunc:

    @staticmethod
    def encrypt_message(message, key):
        # Ensure the AES key length is 16 bytes (AES-128)
        key = key[:16]  # Truncate to 16 bytes if necessary
        iv = os.urandom(16)  # Generate a random 16-byte IV
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = iv + encryptor.update(message) + encryptor.finalize()  # IV prepended to the encrypted data
        return encrypted_message
    
    @staticmethod
    def decrypt_message(encrypted_message, key):
        # Ensure the AES key length is 16 bytes (AES-128)
        key = key[:16]  # Truncate to 16 bytes if necessary
        iv = encrypted_message[:16]  # Extract the IV (first 16 bytes)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()  # Decrypt the rest of the data
        return decrypted_message


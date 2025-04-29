import subprocess
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import win32file

class GlobalFunc:
   
    @staticmethod
    def encrypt_message(message, key):
        key = key[:16]  # Ensure the AES key length is 16 bytes (AES-128)
        iv = os.urandom(16)  # Generate a random 16-byte IV
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = iv + encryptor.update(message) + encryptor.finalize()
        return encrypted_message

    @staticmethod
    def decrypt_message(encrypted_message, key):
        key = key[:16]  # Ensure the AES key length is 16 bytes (AES-128)
        iv = encrypted_message[:16]  # Extract the IV (first 16 bytes)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
        return decrypted_message

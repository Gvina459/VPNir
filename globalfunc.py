import subprocess
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class GlobalFunc:

    @staticmethod
    def get_tap_adapter_name():
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-Command",
                    "netsh interface show interface | Select-String -Pattern 'TAP'"
                ],
                capture_output=True,
                text=True,
                shell=True
            )

            # Check if command was successful
            if result.returncode != 0:
                raise ValueError("Failed to retrieve interface list")

            # Process output to find TAP adapter
            for line in result.stdout.splitlines():
                if "TAP" in line:
                    return line.split()[-1]  # Adjust depending on exact output format
                
            raise ValueError("TAP adapter not found")

        except Exception as e:
            print(f"Error: {e}")
            return None
    
    @staticmethod
    def configure_tap_adapter(adapter_name, ip, mask="255.255.255.0"):
        # Path to your batch file
        bat_file_path = r"ActuallyVPN\p.bat"  # Make sure this path is correct and relative to where the script is running or use an absolute path

        # Run the .bat file as administrator using PowerShell
        subprocess.run([
            "powershell", 
            "-Command", 
            "Start-Process", 
            "cmd.exe", 
            f'"/c {bat_file_path}"',  # Pass the batch file path correctly
            "-Verb", 
            "RunAs"
        ], shell=True)

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


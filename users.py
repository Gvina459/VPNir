import sqlite3
import smtplib
import random
import string
import time
from hashlib import sha256
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class User:
    def __init__(self, email=None, password=None):
        self.conn = sqlite3.connect('user_database.db', check_same_thread=False)
        self.cursor = self.conn.cursor()

        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        ''')

        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            otp TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        )
        ''')

        self.conn.commit()

        self.email = email
        self.password = password

    def hash_password(self):
        if self.password:
            return sha256(self.password.encode()).hexdigest()
        return None

    def verify_user(self):
        password_hash = self.hash_password()
        self.cursor.execute("SELECT * FROM users WHERE email = ? AND password_hash = ?", 
                            (self.email, password_hash))
        user = self.cursor.fetchone()
        return bool(user)

    def add_user(self):
        password_hash = self.hash_password()
        if password_hash:
            try:
                self.cursor.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", 
                                    (self.email, password_hash))
                self.conn.commit()
            except sqlite3.IntegrityError:
                print("Error: Email already exists.")
        else:
            print("Error: Password required to add user.")

    def remove_user(self, email, password):
        password_hash = sha256(password.encode()).hexdigest()
        self.cursor.execute("SELECT * FROM users WHERE email = ? AND password_hash = ?", 
                            (email, password_hash))
        user = self.cursor.fetchone()

        if user:
            self.cursor.execute("DELETE FROM users WHERE email = ? AND password_hash = ?", 
                                (email, password_hash))
            self.conn.commit()

            self.cursor.execute("DELETE FROM otp_codes WHERE email = ?", (email,))
            self.conn.commit()

            print(f"User {email} removed successfully.")
            return True
        else:
            print("Error: User not found or incorrect password.")
            return False

    def send_otp(self, email):
        otp = ''.join(random.choices(string.digits, k=6))
        timestamp = int(time.time())

        self.cursor.execute("DELETE FROM otp_codes WHERE email = ?", (email,))
        self.cursor.execute("INSERT INTO otp_codes (email, otp, timestamp) VALUES (?, ?, ?)", 
                            (email, otp, timestamp))
        self.conn.commit()

        try:
            self.send_email(email, otp)
            print(f"OTP sent successfully to {email}.")
            return True, "OTP sent"
        except Exception as e:
            print("Error sending email:", e)
            return False, f"Failed to send OTP: {e}"

    def send_email(self, recipient_email, otp):
        sender_email = "vpnnir@gmail.com"
        sender_password = "wkjl peeh ouup whqr"
        subject = "Your One-Time Password (OTP)"

        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = recipient_email
        msg["Subject"] = subject
        body = f"Your OTP code is: {otp}\nIt is valid for 5 minutes."
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()

    def verify_otp(self, email, otp_input):
        self.cursor.execute("SELECT otp, timestamp FROM otp_codes WHERE email = ? ORDER BY timestamp DESC LIMIT 1", 
                            (email,))
        otp_record = self.cursor.fetchone()

        if otp_record:
            stored_otp, timestamp = otp_record
            current_time = int(time.time())

            if otp_input == stored_otp and current_time - timestamp <= 300:
                self.cursor.execute("DELETE FROM otp_codes WHERE email = ?", (email,))
                self.conn.commit()
                print(f"OTP verified successfully for {email}. Login granted.")
                return True
            else:
                print("Invalid or expired OTP.")
        else:
            print("No OTP found for this email.")

        return False

# Example Usage
user = User("nirimaim@gmail.com", "mypassword123")
#user.remove_user("nirimaim@gmail.com", "mypassword123")
#user.add_user()  # Adds a user to the database
#user.send_otp("nirimaim@gmail.com")  # Generates and sends an OTP
#user.verify_otp("nirimaim@gmail.com", "840596")  # Replace with actual OTP from email

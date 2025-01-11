import sqlite3
from hashlib import sha256

class User():
    def __init__(self, username, password):
        self.username=username
        self.password=password

        self.conn = sqlite3.connect('user_database.db')
        self.cursor = self.conn.cursor()

        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        ''')
        self.conn.commit()

    def hash_password(self):
        return sha256(self.password.encode()).hexdigest()

    def add_user(self):
        password_hash = self.hash_password()
        try:
            self.cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (self.username, password_hash))
            self.conn.commit()
            print(f"User {self.username} added successfully.")
        except sqlite3.IntegrityError:
            print("Error: Username already exists.")

    def remove_user(self):
        password_hash = self.hash_password()
        try:
            self.cursor.execute("DELETE FROM users WHERE username = ? AND password_hash = ?", (self.username, password_hash))
            self.conn.commit()
            if self.cursor.rowcount > 0: 
                print(f"User {self.username} removed successfully.")
            else:
                print("Error: User not found or incorrect password.")
        except sqlite3.Error as e:
            print("Error:", e)

    def verify_user(self):
        password_hash = self.hash_password()
        self.cursor.execute("SELECT * FROM users WHERE username = ? AND password_hash = ?", (self.username, password_hash))
        user = self.cursor.fetchone()
        if user:
            print("Login successful!")
            return True
        else:
            print("Invalid username or password.")
            return False

#u=User("testuser", "mypassword123")
#u2=User("testuser", "wrongpassword")
#u.add_user()
#u.remove_user()
#u.verify_user()
#u2.verify_user()
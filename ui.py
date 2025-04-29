import tkinter as tk
from tkinter import messagebox
from users import User
from clnt3 import VPNClient
from globalfunc import GlobalFunc

DARK_BG = "#2b2b2b"
TEXT_COLOR = "white"
BUTTON_BG = "#444"
ENTRY_BG = "#3c3f41"

class VPNClientUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ActuallyVPN - Client")
        self.geometry("450x400")
        self.configure(bg=DARK_BG)

        self.user = None
        self.vpn_client = None
        self.auth_method = None
        self.user_password = ""

        self.frames = {}
        container = tk.Frame(self, bg=DARK_BG)
        container.pack(fill="both", expand=True)

        for F in (LoginScreen, OTPVerificationScreen, VPNControlScreen):
            frame = F(parent=container, controller=self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(LoginScreen)

    def show_frame(self, frame_class):
        frame = self.frames[frame_class]
        frame.tkraise()

    def set_user(self, user, auth_method, password=""):
        self.user = user
        self.auth_method = auth_method
        self.user_password = password

    def set_vpn_client(self, vpn_client):
        self.vpn_client = vpn_client


class BaseFrame(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg=DARK_BG)

    def style_entry(self, entry):
        entry.configure(bg=ENTRY_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)

    def style_label(self, label):
        label.configure(bg=DARK_BG, fg=TEXT_COLOR)

    def style_button(self, button):
        button.configure(bg=BUTTON_BG, fg=TEXT_COLOR, activebackground="#666", relief="raised")


class LoginScreen(BaseFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        tk.Label(self, text="Email:", anchor="w").pack(fill="x", padx=40, pady=(20, 0))
        self.email_entry = tk.Entry(self)
        self.style_entry(self.email_entry)
        self.email_entry.pack(fill="x", padx=40, pady=5)

        tk.Label(self, text="Password:", anchor="w").pack(fill="x", padx=40, pady=(10, 0))
        self.password_entry = tk.Entry(self, show="*")
        self.style_entry(self.password_entry)
        self.password_entry.pack(fill="x", padx=40, pady=5)

        login_btn = tk.Button(self, text="Login", command=self.login)
        self.style_button(login_btn)
        login_btn.pack(fill="x", padx=100, pady=10)

        otp_btn = tk.Button(self, text="Forgot Password? Use OTP", command=self.send_otp)
        self.style_button(otp_btn)
        otp_btn.pack(fill="x", padx=100)

        for widget in self.winfo_children():
            if isinstance(widget, tk.Label):
                self.style_label(widget)

    def login(self):
        email = self.email_entry.get()
        password = self.password_entry.get()
        user = User(email, password)

        if user.verify_user():
            self.controller.set_user(user, 'password', password)
            self.controller.show_frame(VPNControlScreen)
        else:
            messagebox.showerror("Login Failed", "Invalid credentials")

    def send_otp(self):
        email = self.email_entry.get()
        if not email:
            messagebox.showerror("Error", "Please enter your email first")
            return

        user = User(email, "")
        if user.send_otp(email):
            self.controller.set_user(user, 'otp')
            messagebox.showinfo("OTP Sent", "Check your email for the OTP")
            self.controller.show_frame(OTPVerificationScreen)
        else:
            messagebox.showerror("Error", "Failed to send OTP")


class OTPVerificationScreen(BaseFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        tk.Label(self, text="Enter OTP sent to your email:").pack(pady=20)
        self.otp_entry = tk.Entry(self)
        self.style_entry(self.otp_entry)
        self.otp_entry.pack(fill="x", padx=40, pady=5)

        verify_btn = tk.Button(self, text="Verify OTP", command=self.verify_otp)
        self.style_button(verify_btn)
        verify_btn.pack(fill="x", padx=100, pady=10)

        back_btn = tk.Button(self, text="Back to Login", command=lambda: self.controller.show_frame(LoginScreen))
        self.style_button(back_btn)
        back_btn.pack(fill="x", padx=100)

        for widget in self.winfo_children():
            if isinstance(widget, tk.Label):
                self.style_label(widget)

    def verify_otp(self):
        otp = self.otp_entry.get()
        user = self.controller.user

        if user and user.verify_otp(user.email, otp):
            messagebox.showinfo("Success", "OTP verified successfully")
            self.controller.show_frame(VPNControlScreen)
        else:
            messagebox.showerror("Error", "Invalid OTP")


class VPNControlScreen(BaseFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        self.connection_status = tk.Label(self, text="Status: Disconnected", fg="red", bg=DARK_BG)
        self.connection_status.pack(pady=5)

        connect_btn = tk.Button(self, text="Connect to VPN", command=self.connect_vpn)
        self.style_button(connect_btn)
        connect_btn.pack(fill="x", padx=100, pady=10)

        self.message_entry = tk.Entry(self)
        self.style_entry(self.message_entry)
        self.message_entry.pack(fill="x", padx=40, pady=5)

        send_btn = tk.Button(self, text="Send Message", command=self.send_message)
        self.style_button(send_btn)
        send_btn.pack(fill="x", padx=100, pady=5)

        self.output_text = tk.Text(self, height=10, bg=ENTRY_BG, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
        self.output_text.pack(fill="both", expand=True, padx=10, pady=10)

        disconnect_btn = tk.Button(self, text="Disconnect VPN", command=self.disconnect_vpn)
        self.style_button(disconnect_btn)
        disconnect_btn.pack(fill="x", padx=100, pady=5)

        logout_btn = tk.Button(self, text="Logout", command=self.logout)
        self.style_button(logout_btn)
        logout_btn.pack(fill="x", padx=100, pady=5)

    def connect_vpn(self):
        user = self.controller.user
        if not user:
            messagebox.showerror("Error", "Not logged in")
            return

        vpn_client = VPNClient("localhost", 50001, cafile="ActuallyVPN/server.crt")

        try:
            if self.controller.auth_method == 'otp':
                vpn_client.connect_otp(user.email)
            else:
                vpn_client.connect(user.email, self.controller.user_password)

            self.controller.set_vpn_client(vpn_client)
            self.connection_status.config(text="Status: Connected", fg="green")
            messagebox.showinfo("Connected", "VPN connection established")
        except Exception as e:
            messagebox.showerror("Connection Failed", str(e))

    def send_message(self):
        vpn_client = self.controller.vpn_client
        if not vpn_client or not vpn_client.secure_socket:
            messagebox.showerror("Error", "Not connected to VPN")
            return

        message = self.message_entry.get()
        if not message:
            return

        try:
            encrypted = GlobalFunc.encrypt_message(message.encode(), vpn_client.symmetric_key)
            vpn_client.secure_socket.sendall(encrypted)
            self.output_text.insert("end", f"Sent: {message}\n")

            response = vpn_client.secure_socket.recv(4096)
            decrypted = GlobalFunc.decrypt_message(response, vpn_client.symmetric_key)
            self.output_text.insert("end", f"Received: {decrypted.decode()}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")

    def disconnect_vpn(self):
        if self.controller.vpn_client:
            self.controller.vpn_client.disconnect()
            self.controller.set_vpn_client(None)
            self.connection_status.config(text="Status: Disconnected", fg="red")
        messagebox.showinfo("Disconnected", "VPN Disconnected")

    def logout(self):
        self.disconnect_vpn()
        self.controller.user = None
        self.controller.auth_method = None
        self.controller.user_password = ""
        self.controller.show_frame(LoginScreen)


if __name__ == "__main__":
    app = VPNClientUI()
    app.mainloop()

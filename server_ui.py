import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
import threading
import queue
from datetime import datetime
import time
import os
import sys
from srv3 import VPNServer

DARK_BG = "#2b2b2b"
TEXT_COLOR = "white"
BUTTON_BG = "#444"
ENTRY_BG = "#3c3f41"

class VPNServerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ActuallyVPN - Server")
        self.root.geometry("900x600")
        self.root.configure(bg=DARK_BG)

        self.server = None
        self.server_thread = None
        self.server_running = False
        self.active_connections = 0
        self.start_time = None
        self.log_queue = queue.Queue()

        self.setup_ui()
        self.update_ui()

    def setup_ui(self):
        self.main_frame = tk.Frame(self.root, bg=DARK_BG)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.header_frame = tk.Frame(self.main_frame, bg=DARK_BG)
        self.header_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(self.header_frame, text="ActuallyVPN - Server Dashboard", bg=DARK_BG,
                 fg=TEXT_COLOR, font=('Arial', 14, 'bold')).pack(side=tk.LEFT)

        self.status_label = tk.Label(self.header_frame, text="Status: Stopped", bg=DARK_BG,
                                     fg="red", font=('Arial', 12))
        self.status_label.pack(side=tk.RIGHT)

        self.stats_frame = tk.LabelFrame(self.main_frame, text="Server Statistics", bg=DARK_BG,
                                         fg=TEXT_COLOR, font=('Arial', 10, 'bold'), bd=2, relief="groove")
        self.stats_frame.pack(fill=tk.X, pady=(0, 10))

        self.connections_label = tk.Label(self.stats_frame, text="Active Connections: 0",
                                          bg=DARK_BG, fg=TEXT_COLOR)
        self.connections_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)

        self.port_label = tk.Label(self.stats_frame, text="Listening Port: Not active",
                                   bg=DARK_BG, fg=TEXT_COLOR)
        self.port_label.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)

        self.uptime_label = tk.Label(self.stats_frame, text="Uptime: 00:00:00",
                                     bg=DARK_BG, fg=TEXT_COLOR)
        self.uptime_label.grid(row=0, column=2, padx=10, pady=5, sticky=tk.W)

        self.logs_frame = tk.LabelFrame(self.main_frame, text="Server Logs", bg=DARK_BG,
                                        fg=TEXT_COLOR, font=('Arial', 10, 'bold'), bd=2, relief="groove")
        self.logs_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(
            self.logs_frame,
            wrap=tk.WORD,
            font=('Consolas', 10),
            bg=ENTRY_BG,
            fg=TEXT_COLOR,
            insertbackground=TEXT_COLOR
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.configure(state='disabled')

        self.button_frame = tk.Frame(self.main_frame, bg=DARK_BG)
        self.button_frame.pack(fill=tk.X, pady=(10, 0))

        self.start_button = tk.Button(self.button_frame, text="Start Server", command=self.start_server)
        self.style_button(self.start_button)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(self.button_frame, text="Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.style_button(self.stop_button)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = tk.Button(self.button_frame, text="Clear Logs", command=self.clear_logs)
        self.style_button(self.clear_button)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        exit_button = tk.Button(self.button_frame, text="Exit", command=self.on_close, bg="#900", fg="white",
                                activebackground="#b00")
        exit_button.pack(side=tk.RIGHT, padx=5)

    def style_button(self, button):
        button.configure(bg=BUTTON_BG, fg=TEXT_COLOR, activebackground="#666", relief="raised")

    def log_message(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_queue.put(f"[{timestamp}] {message}\n")

    def process_log_queue(self):
        while not self.log_queue.empty():
            message = self.log_queue.get()
            self.log_text.configure(state='normal')
            self.log_text.insert(tk.END, message)
            self.log_text.configure(state='disabled')
            self.log_text.see(tk.END)

    def clear_logs(self):
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state='disabled')

    def start_server(self):
        if not self.server_running:
            try:
                certfile = "ActuallyVPN/server.crt"
                keyfile = "ActuallyVPN/server.key"
                if not os.path.exists(certfile) or not os.path.exists(keyfile):
                    messagebox.showerror("Error", f"Certificate files not found:\n{certfile}\n{keyfile}")
                    return

                self.log_message("Starting VPN server...")
                self.server = VPNServer(port=50001, certfile=certfile, keyfile=keyfile)

                sys.stdout = PrintLogger(self.log_message)
                sys.stderr = PrintLogger(self.log_message)

                self.server_running = True
                self.start_time = datetime.now()
                self.server_thread = threading.Thread(target=self.server.run, daemon=True)
                self.server_thread.start()

                self.status_label.config(text="Status: Running", fg="green")
                self.port_label.config(text=f"Listening Port: {self.server.port}")
                self.start_button.config(state=tk.DISABLED)
                self.stop_button.config(state=tk.NORMAL)
                self.log_message("VPN Server is now running")

            except Exception as e:
                self.log_message(f"Failed to start server: {str(e)}")
                self.server_running = False
                if self.server:
                    self.server = None

    def stop_server(self):
        if self.server_running:
            self.log_message("Stopping VPN server...")
            self.server_running = False
            self.active_connections = 0
            self.status_label.config(text="Status: Stopped", fg="red")
            self.port_label.config(text="Listening Port: Not active")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.log_message("VPN Server has been stopped")

    def update_ui(self):
        self.process_log_queue()
        if self.server_running and self.start_time:
            uptime = datetime.now() - self.start_time
            self.uptime_label.config(text=f"Uptime: {str(uptime).split('.')[0]}")
        self.root.after(200, self.update_ui)

    def on_close(self):
        if self.server_running:
            if messagebox.askokcancel("Quit", "Server is still running. Are you sure you want to exit?"):
                self.stop_server()
                self.root.destroy()
        else:
            self.root.destroy()

class PrintLogger:
    def __init__(self, log_func):
        self.log_func = log_func

    def write(self, message):
        if message.strip():
            self.log_func(message)

    def flush(self):
        pass 


def main():
    root = tk.Tk()
    app = VPNServerUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()

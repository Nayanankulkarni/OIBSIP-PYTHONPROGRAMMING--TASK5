import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox, filedialog
import socket
import threading
import sqlite3
from cryptography.fernet import Fernet
from PIL import Image, ImageTk
import io
import base64
import os

# ------------------- ENCRYPTION -------------------
key_file = "secret.key"
if os.path.exists(key_file):
    with open(key_file, "rb") as f:
        key = f.read()
else:
    key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(key)
fernet = Fernet(key)

def encrypt(msg):
    return fernet.encrypt(msg.encode())

def decrypt(token):
    return fernet.decrypt(token).decode()

# ------------------- DATABASE -------------------
db_file = "chat_history.db"
conn = sqlite3.connect(db_file)
c = conn.cursor()

# Ensure users table exists
c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)''')

# Ensure messages table exists and correct schema
def ensure_messages_table():
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'")
    if not c.fetchone():
        c.execute('''CREATE TABLE messages (sender TEXT, receiver TEXT, message TEXT)''')
        conn.commit()
    else:
        c.execute("PRAGMA table_info(messages)")
        columns = [info[1] for info in c.fetchall()]
        required = ["sender", "receiver", "message"]
        if columns != required:
            c.execute("ALTER TABLE messages RENAME TO messages_old")
            c.execute('''CREATE TABLE messages (sender TEXT, receiver TEXT, message TEXT)''')
            if "message" in columns:
                c.execute("INSERT INTO messages(message) SELECT message FROM messages_old")
            c.execute("DROP TABLE messages_old")
            conn.commit()

ensure_messages_table()

# ------------------- SERVER -------------------
clients = {}  # username -> socket

def broadcast_user_list():
    user_list = ",".join(clients.keys())
    for sock in clients.values():
        try:
            sock.send(encrypt(f"/users:{user_list}"))
        except:
            continue

def handle_client(client, addr):
    try:
        username = decrypt(client.recv(4096))
        clients[username] = client
        broadcast_user_list()
    except:
        return
    while True:
        try:
            data = decrypt(client.recv(8192))
            if data.startswith("/pm"):
                parts = data.split(" ", 2)
                if len(parts) < 3:
                    continue
                target, msg = parts[1], parts[2]
                if target in clients:
                    clients[target].send(encrypt(f"[PM from {username}]: {msg}"))
                    # Save to DB
                    c.execute("INSERT INTO messages VALUES (?, ?, ?)", (username, target, msg))
                    conn.commit()
        except:
            if username in clients:
                del clients[username]
            broadcast_user_list()
            break

def start_server(host="127.0.0.1", port=12345):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    print(f"Server running on {host}:{port}")
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()

# ------------------- CLIENT -------------------
class ChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("1-to-1 Encrypted Chat")
        self.frame = tk.Frame(master)
        self.frame.pack(padx=10, pady=10)

        # --- Login ---
        self.username = simpledialog.askstring("Username", "Enter username:", parent=master)
        if not self.username:
            messagebox.showerror("Error", "Username required")
            master.destroy()
            return

        password = simpledialog.askstring("Password", "Enter password:", show='*', parent=master)
        if not password:
            messagebox.showerror("Error", "Password required")
            master.destroy()
            return

        # Authentication
        c.execute("SELECT password FROM users WHERE username=?", (self.username,))
        row = c.fetchone()
        if row:
            if row[0] != password:
                messagebox.showerror("Login Failed", "Incorrect password!")
                master.destroy()
                return
        else:
            c.execute("INSERT INTO users VALUES (?, ?)", (self.username, password))
            conn.commit()

        # --- GUI ---
        self.left_frame = tk.Frame(self.frame)
        self.left_frame.pack(side=tk.LEFT, padx=5)
        self.right_frame = tk.Frame(self.frame)
        self.right_frame.pack(side=tk.LEFT, padx=5)

        tk.Label(self.left_frame, text="Online Users").pack()
        self.user_listbox = tk.Listbox(self.left_frame, height=20, width=20)
        self.user_listbox.pack()
        self.user_listbox.bind("<<ListboxSelect>>", self.select_user)
        self.selected_user = None

        self.text_area = scrolledtext.ScrolledText(self.right_frame, state='disabled', width=50, height=20)
        self.text_area.pack(pady=5)

        self.msg_entry = tk.Entry(self.right_frame, width=30)
        self.msg_entry.pack(side=tk.LEFT, pady=5)

        self.send_btn = tk.Button(self.right_frame, text="Send", command=self.send_message)
        self.send_btn.pack(side=tk.LEFT, padx=5)

        self.image_btn = tk.Button(self.right_frame, text="Send Image", command=self.send_image)
        self.image_btn.pack(side=tk.LEFT, padx=5)

        # --- Socket ---
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect(("127.0.0.1", 12345))
            self.sock.send(encrypt(self.username))
        except:
            messagebox.showerror("Error", "Cannot connect to server. Start server first.")
            master.destroy()
            return

        threading.Thread(target=self.receive_messages, daemon=True).start()
        self.load_history()

    def load_history(self):
        try:
            c.execute("SELECT sender, message FROM messages WHERE receiver=?", (self.username,))
            for sender, msg in c.fetchall():
                self.text_area.config(state='normal')
                self.text_area.insert(tk.END, f"[From {sender}]: {msg}\n")
                self.text_area.config(state='disabled')
        except:
            pass

    def select_user(self, event):
        if not self.user_listbox.curselection():
            return
        index = self.user_listbox.curselection()[0]
        self.selected_user = self.user_listbox.get(index)

    def send_message(self):
        # Auto-select first user if none selected
        if not self.selected_user:
            if self.user_listbox.size() > 0:
                self.selected_user = self.user_listbox.get(0)
            else:
                messagebox.showwarning("Warning", "No users online.")
                return
        msg = self.msg_entry.get().strip()
        if msg:
            try:
                self.sock.send(encrypt(f"/pm {self.selected_user} {msg}"))
                self.text_area.config(state='normal')
                self.text_area.insert(tk.END, f"[To {self.selected_user}]: {msg}\n")
                self.text_area.config(state='disabled')
                self.text_area.yview(tk.END)
                self.msg_entry.delete(0, tk.END)
            except:
                messagebox.showerror("Error", "Disconnected from server.")

    def send_image(self):
        if not self.selected_user:
            if self.user_listbox.size() > 0:
                self.selected_user = self.user_listbox.get(0)
            else:
                messagebox.showwarning("Warning", "No users online.")
                return
        path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.gif")])
        if path:
            with open(path, "rb") as f:
                data = base64.b64encode(f.read()).decode()
            try:
                self.sock.send(encrypt(f"/pm {self.selected_user} /img:{data}"))
                self.display_image(path, f"[To {self.selected_user}]")
            except:
                messagebox.showerror("Error", "Disconnected from server.")

    def display_image(self, path, prefix=""):
        img = Image.open(path)
        img.thumbnail((100, 100))
        img = ImageTk.PhotoImage(img)
        self.text_area.config(state='normal')
        if prefix:
            self.text_area.insert(tk.END, f"{prefix} sent an image:\n")
        self.text_area.image_create(tk.END, image=img)
        self.text_area.insert(tk.END, "\n")
        self.text_area.config(state='disabled')
        self.text_area.yview(tk.END)
        self.text_area.img_ref = img

    def receive_messages(self):
        while True:
            try:
                msg = decrypt(self.sock.recv(8192))
                if msg.startswith("/users:"):
                    users = msg[7:].split(",")
                    self.user_listbox.delete(0, tk.END)
                    for u in users:
                        if u != self.username:
                            self.user_listbox.insert(tk.END, u)
                elif msg.startswith("/img:"):
                    data = base64.b64decode(msg[5:])
                    img = Image.open(io.BytesIO(data))
                    img.thumbnail((100, 100))
                    img = ImageTk.PhotoImage(img)
                    self.text_area.config(state='normal')
                    self.text_area.image_create(tk.END, image=img)
                    self.text_area.insert(tk.END, "\n")
                    self.text_area.config(state='disabled')
                    self.text_area.yview(tk.END)
                    self.text_area.img_ref = img
                else:
                    self.text_area.config(state='normal')
                    self.text_area.insert(tk.END, msg + "\n")
                    self.text_area.config(state='disabled')
                    self.text_area.yview(tk.END)
            except:
                break

# ------------------- MAIN -------------------
if __name__ == "__main__":
    choice = input("Run as server (s) or client (c)? ").lower()
    if choice == "s":
        start_server()
    else:
        root = tk.Tk()
        ChatClient(root)
        root.mainloop()

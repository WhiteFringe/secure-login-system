import os
import json
import socket
import hashlib
import uuid
import re
import dh_aes
import tkinter as tk
from tkinter import messagebox

SERVER_HOST = 'localhost'
SERVER_PORT = 5000
TOKEN_DIR = os.path.join(os.path.dirname(__file__), "Tokens")

if not os.path.exists(TOKEN_DIR):
    os.makedirs(TOKEN_DIR)


def send_encrypted(conn, data, aes_key):
    encrypted_data = dh_aes.aes_encrypt(data, aes_key)
    conn.sendall(len(encrypted_data).to_bytes(4, 'big'))
    conn.sendall(encrypted_data)
    print(f"[INFO] Sent {len(encrypted_data)} bytes securely.")

def receive_encrypted(sock, aes_key):
    length_data = sock.recv(4)
    if not length_data:
        return ""
    length = int.from_bytes(length_data, 'big')
    encrypted_data = b''
    while len(encrypted_data) < length:
        chunk = sock.recv(length - len(encrypted_data))
        if not chunk:
            break
        encrypted_data += chunk
    if len(encrypted_data) != length:
        print(f"[ERROR] Expected {length} bytes but received {len(encrypted_data)}.")
        return ""
    try:
        decrypted = dh_aes.aes_decrypt(encrypted_data, aes_key)
        return decrypted
    except Exception as e:
        print("[ERROR] Decryption failed:", e)
        return ""


def is_password_strong(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )

def get_mac_hash():
    mac = hex(uuid.getnode())
    return hashlib.sha256(mac.encode()).hexdigest()

def save_token(username, token):
    with open(os.path.join(TOKEN_DIR, f"{username}_token.txt"), "w") as f:
        f.write(token)
    print(f"[INFO] Token saved for user: {username}")

def load_token(username):
    token_file = os.path.join(TOKEN_DIR, f"{username}_token.txt")
    if os.path.exists(token_file):
        with open(token_file, "r") as f:
            return f.read().strip()
    return ""

def communicate_with_server(payload):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_HOST, SERVER_PORT))

        priv_client, pub_client = dh_aes.generate_dh_keys()
        server_pub = int(s.recv(1024).decode())
        s.sendall(str(pub_client).encode())
        aes_key = dh_aes.compute_shared_key(server_pub, priv_client)

        send_encrypted(s, json.dumps(payload), aes_key)
        response = receive_encrypted(s, aes_key)

        if not response:
            return {"status": "fail", "msg": "Empty or invalid response from server"}

        return json.loads(response)
    except Exception as e:
        print("[ERROR] Communication failed:", e)
        return {"status": "fail", "msg": str(e)}
    finally:
        s.close()

def handle_register(username, password):
    if not is_password_strong(password):
        messagebox.showerror("Error", "Password must have 8+ chars, 1 uppercase, 1 number, 1 special character.")
        return
    mac_hash = get_mac_hash()
    response = communicate_with_server({"action":"register","username":username,"password":password,"mac_hash":mac_hash})
    if response.get('status') == 'success':
        save_token(username, response['token'])
        messagebox.showinfo("Success", "Registered and token saved.")
    else:
        messagebox.showerror("Error", response.get('msg', 'Registration failed.'))

def handle_login(username, password):
    token = load_token(username)
    mac_hash = get_mac_hash()
    response = communicate_with_server({"action":"login","username":username,"password":password,"mac_hash":mac_hash,"token":token})
    if response.get('status') == 'success':
        messagebox.showinfo("Success", "Login successful.")
    else:
        messagebox.showerror("Error", response.get('msg', 'Login failed.'))

def create_gui():
    root = tk.Tk()
    root.title("Secure Login")
    root.attributes('-fullscreen', True)  # Fullscreen
    root.bind('<Escape>', lambda e: root.destroy())  # ESC to close

    frame = tk.Frame(root)
    frame.place(relx=0.5, rely=0.5, anchor='center')

    tk.Label(frame, text="Username:", font=("Arial", 16)).grid(row=0, column=0, padx=10, pady=10)
    tk.Label(frame, text="Password:", font=("Arial", 16)).grid(row=1, column=0, padx=10, pady=10)

    username_entry = tk.Entry(frame, font=("Arial", 16))
    password_entry = tk.Entry(frame, show="*", font=("Arial", 16))
    username_entry.grid(row=0, column=1, padx=10, pady=10)
    password_entry.grid(row=1, column=1, padx=10, pady=10)

    tk.Button(frame, text="Register", font=("Arial", 16), command=lambda: handle_register(username_entry.get(), password_entry.get())).grid(row=2, column=0, padx=10, pady=10)
    tk.Button(frame, text="Login", font=("Arial", 16), command=lambda: handle_login(username_entry.get(), password_entry.get())).grid(row=2, column=1, padx=10, pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()

import tkinter as tk
from tkinter import messagebox, scrolledtext
import database
import auth
import dh_aes
import context_utils
import blockchain
import json

database.create_db()
aes_key = dh_aes.compute_shared_key()

def register_user():
    username = entry_username.get()
    password = entry_password.get()
    gps = context_utils.get_gps_location()
    mac = context_utils.get_mac()
    password_hash, status = auth.register_user(username, password)
    if password_hash is None:
        error_label.config(text=status, fg="red")
        return
    iv_gps, gps_ct = dh_aes.aes_encrypt(gps, aes_key)
    iv_mac, mac_ct = dh_aes.aes_encrypt(mac, aes_key)
    database.add_user_extended(username, password_hash, gps_ct, mac_ct, iv_gps, iv_mac)
    messagebox.showinfo("Success", "User registered successfully!")

def login_user():
    username = entry_username.get()
    password = entry_password.get()
    gps = context_utils.get_gps_location()
    mac = context_utils.get_mac()
    if not auth.verify_user(username, password, database.get_password_hash):
        blockchain.add_login_attempt(username, gps, mac, "FAILURE")
        error_label.config(text="Invalid username or password.", fg="red")
        return
    gps_enc_stored, mac_enc_stored, iv_gps, iv_mac = database.get_encrypted_context(username)
    if not gps_enc_stored or not mac_enc_stored:
        blockchain.add_login_attempt(username, gps, mac, "FAILURE")
        error_label.config(text="Context not found.", fg="red")
        return
    gps_dec = dh_aes.aes_decrypt(gps_enc_stored, iv_gps, aes_key)
    mac_dec = dh_aes.aes_decrypt(mac_enc_stored, iv_mac, aes_key)
    if gps == gps_dec and mac == mac_dec:
        blockchain.add_login_attempt(username, gps, mac, "SUCCESS")
        messagebox.showinfo("Login Success", "Login successful and context verified!")
        error_label.config(text="")
    else:
        blockchain.add_login_attempt(username, gps, mac, "FAILURE")
        error_label.config(text="GPS/MAC verification failed.", fg="red")

def view_audit_log():
    try:
        with open('blockchain.json', 'r') as f:
            data = json.load(f)
            log_text = json.dumps(data, indent=4)
    except FileNotFoundError:
        log_text = "No audit log found."
    log_window = tk.Toplevel(root)
    log_window.title("Audit Log")
    log_window.geometry("700x500")
    scrolled = scrolledtext.ScrolledText(log_window, wrap=tk.WORD)
    scrolled.pack(fill=tk.BOTH, expand=True)
    scrolled.insert(tk.END, log_text)

root = tk.Tk()
root.title("Secure Login System with Blockchain")
root.attributes('-zoomed', True)  # Fullscreen

tk.Label(root, text="Username", font=("Arial", 14)).pack(pady=10)
entry_username = tk.Entry(root, font=("Arial", 14))
entry_username.pack(pady=10)

tk.Label(root, text="Password", font=("Arial", 14)).pack(pady=10)
entry_password = tk.Entry(root, show="*", font=("Arial", 14))
entry_password.pack(pady=10)

error_label = tk.Label(root, text="", font=("Arial", 12))
error_label.pack(pady=5)

tk.Button(root, text="Register", command=register_user, font=("Arial", 14), width=12).pack(pady=10)
tk.Button(root, text="Login", command=login_user, font=("Arial", 14), width=12).pack(pady=10)
tk.Button(root, text="View Audit Log", command=view_audit_log, font=("Arial", 14), width=15).pack(pady=10)

root.mainloop()

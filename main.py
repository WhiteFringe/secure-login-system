import tkinter as tk
from tkinter import messagebox
import database
import auth
import dh_aes
import context_utils

database.create_db()
aes_key = dh_aes.compute_shared_key()

def register_user():
    username = entry_username.get()
    password = entry_password.get()
    gps = context_utils.get_gps_location()
    mac = context_utils.get_mac()
    password_hash, status = auth.register_user(username, password)
    if password_hash is None:
        messagebox.showerror("Error", status)
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
        messagebox.showerror("Login Failed", "Invalid username or password.")
        return
    gps_enc_stored, mac_enc_stored, iv_gps, iv_mac = database.get_encrypted_context(username)
    if not gps_enc_stored or not mac_enc_stored:
        messagebox.showerror("Login Failed", "Context not found.")
        return
    gps_dec = dh_aes.aes_decrypt(gps_enc_stored, iv_gps, aes_key)
    mac_dec = dh_aes.aes_decrypt(mac_enc_stored, iv_mac, aes_key)
    if gps == gps_dec and mac == mac_dec:
        messagebox.showinfo("Login Success", "Login successful and context verified!")
    else:
        messagebox.showerror("Login Failed", "GPS/MAC verification failed.")

root = tk.Tk()
root.title("Secure Login System")

tk.Label(root, text="Username").grid(row=0, column=0, padx=10, pady=5)
entry_username = tk.Entry(root)
entry_username.grid(row=0, column=1, padx=10, pady=5)

tk.Label(root, text="Password").grid(row=1, column=0, padx=10, pady=5)
entry_password = tk.Entry(root, show="*")
entry_password.grid(row=1, column=1, padx=10, pady=5)

tk.Button(root, text="Register", command=register_user).grid(row=2, column=0, padx=10, pady=10)
tk.Button(root, text="Login", command=login_user).grid(row=2, column=1, padx=10, pady=10)

root.mainloop()

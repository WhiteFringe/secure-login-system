import os
import socket
import json
import sqlite3
import bcrypt
from datetime import datetime, timedelta
import dh_aes

import re
def is_password_strong(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )


HOST = '0.0.0.0'
PORT = 5000
DB = 'users.db'


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


def create_db():
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        mac_hash TEXT NOT NULL,
        token TEXT,
        token_expiry TEXT
    )''')
    conn.commit()
    conn.close()

create_db()

def generate_token(username, days=30):
    expiry = datetime.now() + timedelta(days=days)
    token_raw = username + str(expiry) + os.urandom(16).hex()
    token = bcrypt.hashpw(token_raw.encode(), bcrypt.gensalt()).decode()
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET token=?, token_expiry=? WHERE username=?',
                   (token, expiry.isoformat(), username))
    conn.commit()
    conn.close()
    print(f"[INFO] Token generated for user: {username} with expiry: {expiry}")
    return token, expiry.isoformat()

def validate_token(username, token):
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute('SELECT token, token_expiry FROM users WHERE username=?', (username,))
    result = cursor.fetchone()
    conn.close()
    if not result:
        return False
    stored_token, expiry = result
    return stored_token == token and datetime.fromisoformat(expiry) > datetime.now()

def register_user(username, password, mac_hash):
    if not is_password_strong(password):
        return False, "Weak password. Must have 8+ chars, 1 uppercase, 1 number, 1 special character."
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username=?', (username,))
    if cursor.fetchone():
        conn.close()
        return False, "Username already exists"
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    cursor.execute('INSERT INTO users (username, password_hash, mac_hash) VALUES (?, ?, ?)',
                   (username, password_hash, mac_hash))
    conn.commit()
    conn.close()
    print(f"[INFO] New user registered: {username}")
    token, expiry = generate_token(username)
    return True, (token, expiry)

def login_user(username, password, mac_hash, token):
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash, mac_hash FROM users WHERE username=?', (username,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False, "User not found"
    stored_hash, stored_mac_hash = row
    if not bcrypt.checkpw(password.encode(), stored_hash.encode()):
        conn.close()
        return False, "Invalid password"
    if stored_mac_hash != mac_hash:
        conn.close()
        return False, "MAC address mismatch"
    if not validate_token(username, token):
        conn.close()
        return False, "Token invalid or expired"
    conn.close()
    print(f"[INFO] User {username} logged in successfully.")
    return True, "Login successful"

def handle_client(conn):
    try:
        priv_server, pub_server = dh_aes.generate_dh_keys()
        conn.sendall(str(pub_server).encode())
        client_pub = int(conn.recv(1024).decode())
        aes_key = dh_aes.compute_shared_key(client_pub, priv_server)

        decrypted_json = receive_encrypted(conn, aes_key)
        if not decrypted_json:
            send_encrypted(conn, json.dumps({"status": "fail", "msg": "Empty request"}), aes_key)
            return

        request = json.loads(decrypted_json)
        action = request.get('action')
        username = request.get('username')

        if action == 'register':
            password = request.get('password')
            mac_hash = request.get('mac_hash')
            ok, result = register_user(username, password, mac_hash)
            if ok:
                token, expiry = result
                send_encrypted(conn, json.dumps({"status": "success", "token": token, "expiry": expiry}), aes_key)
            else:
                send_encrypted(conn, json.dumps({"status": "fail", "msg": result}), aes_key)

        elif action == 'login':
            password = request.get('password')
            mac_hash = request.get('mac_hash')
            token = request.get('token')
            ok, msg = login_user(username, password, mac_hash, token)
            send_encrypted(conn, json.dumps({"status": "success" if ok else "fail", "msg": msg}), aes_key)

        else:
            send_encrypted(conn, json.dumps({"status": "fail", "msg": "Invalid action"}), aes_key)

    except Exception as e:
        print(f"[SERVER ERROR] {e}")
        try:
            send_encrypted(conn, json.dumps({"status": "fail", "msg": str(e)}), aes_key)
        except:
            pass
    finally:
        conn.close()

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()
    print(f"[SERVER] Listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        print(f"[SERVER] Connection from {addr}")
        handle_client(conn)

if __name__ == '__main__':
    main()

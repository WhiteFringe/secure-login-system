import sqlite3
import os

def create_db():
    if not os.path.exists('users.db'):
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                gps_enc BLOB,
                mac_enc BLOB,
                iv_gps BLOB,
                iv_mac BLOB
            )
        ''')
        conn.commit()
        conn.close()

def add_user_extended(username, password_hash, gps_enc, mac_enc, iv_gps, iv_mac):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO users (username, password_hash, gps_enc, mac_enc, iv_gps, iv_mac)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, password_hash, gps_enc, mac_enc, iv_gps, iv_mac))
        conn.commit()
    except sqlite3.IntegrityError:
        print("[!] User already exists.")
    finally:
        conn.close()

def get_password_hash(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE username=?', (username,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def get_encrypted_context(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT gps_enc, mac_enc, iv_gps, iv_mac FROM users WHERE username=?', (username,))
    result = cursor.fetchone()
    conn.close()
    return result if result else (None, None, None, None)

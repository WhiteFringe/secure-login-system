import bcrypt
import database

def register_user(username, password):
    password_bytes = password.encode('utf-8')
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    database.add_user(username, hashed.decode('utf-8'))
    print("[+] User registered successfully.")

def verify_user(username, password):
    stored_hash = database.get_password_hash(username)
    if not stored_hash:
        return False

    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

print("Hello")
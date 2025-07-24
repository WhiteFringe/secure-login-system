import bcrypt
import re

def validate_password(password):
    if (len(password) >= 8 and
        re.search(r"[A-Za-z]", password) and
        re.search(r"\d", password) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        return True
    return False

def register_user(username, password):
    if not validate_password(password):
        return None, "Password must be 8+ characters long, with one letter, one number, and one special character."
    password_bytes = password.encode('utf-8')
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return hashed.decode('utf-8'), "Success"

def verify_user(username, password, get_password_hash_func):
    stored_hash = get_password_hash_func(username)
    if not stored_hash:
        return False
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

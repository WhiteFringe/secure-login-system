import database
import auth
import dh_aes

def main():
    database.create_db()
    print("1. Register\n2. Login")
    choice = input("Choose option: ")

    username = input("Username: ")
    password = input("Password: ")

    if choice == '1':
        auth.register_user(username, password)

    elif choice == '2':
        if auth.verify_user(username, password):
            print("[+] Login successful!")

            # Diffie-Hellman Key Exchange Simulation
            priv1, pub1 = dh_aes.generate_dh_keys()
            priv2, pub2 = dh_aes.generate_dh_keys()

            key1 = dh_aes.compute_shared_key(pub2, priv1)
            key2 = dh_aes.compute_shared_key(pub1, priv2)

            assert key1 == key2
            aes_key = key1

            # Simulated sensitive data
            secret = "GPS=43.14,80.24|MAC=AA:BB:CC:DD"
            iv, ct = dh_aes.aes_encrypt(secret, aes_key)

            print("[+] Encrypted data:", ct.hex())
            decrypted = dh_aes.aes_decrypt(ct, iv, aes_key)
            print("[+] Decrypted data:", decrypted)

        else:
            print("[-] Login failed.")

if __name__ == "__main__":
    main()

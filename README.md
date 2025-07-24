# Secure Login System with AES, Diffie-Hellman & Token Validation

## Overview
This project is a **secure login system** designed for robust authentication using:
- **AES (Advanced Encryption Standard)** for password and data encryption.
- **Diffie-Hellman key exchange** for generating shared AES keys securely.
- **Token-based authentication** for 30-day login sessions.
- **MAC address verification** for device-level security.
- **Tkinter GUI** for user-friendly login and registration.

---

## Features
1. **Secure Registration & Login**
   - Passwords are hashed using `bcrypt`.
   - Passwords must meet strong security requirements (min 8 chars, 1 uppercase, 1 number, 1 special character).

2. **Token-based Authentication**
   - Tokens are issued for 30 days and stored as `{username}_token.txt` in the client `Tokens` directory.
   - Server validates tokens during login attempts.

3. **AES & Diffie-Hellman Security**
   - AES-CBC is used to encrypt communication.
   - Each session performs a Diffie-Hellman key exchange to generate a unique AES key.

4. **MAC Address Validation**
   - Server verifies the client device using a hashed MAC address.

5. **GUI**
   - Tkinter-based login and registration screen.
   - Full-screen window with **ESC key** to close the application.

6. **Dockerized Deployment**
   - Server runs inside Docker, while client runs locally or in a separate container.

---

## Project Structure
```
SecureLogin/
│
├── server/
│   ├── server.py           # Server code
│   ├── dh_aes.py           # AES & Diffie-Hellman utilities
│   └── users.db            # SQLite database (auto-created)
│
├── client/
│   ├── client.py           # Client GUI
│   ├── dh_aes.py           # AES & Diffie-Hellman utilities
│   └── Tokens/             # User tokens
│
├── requirements.txt        # Python dependencies
├── Dockerfile              # Server Dockerfile
├── docker-compose.yml      # Docker Compose setup
└── README.md               # Project documentation
```

---

## Requirements
- **Python 3.12+**
- Dependencies are listed in `requirements.txt`:
  ```
  python==3.12.4
  bcrypt==4.1.2
  pycryptodome==3.20.0
  tk==0.1.0
  requests==2.31.0
  ```

---

## Installation

### 1. Clone the repository
```bash
git clone <repo_url>
cd SecureLogin
```

### 2. Set up virtual environment
```bash
python3 -m venv env
source env/bin/activate  # Linux/Mac
env\Scripts\activate     # Windows
```

### 3. Install dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Usage

### Start the Server
```bash
cd server
python3 server.py
```
The server will start on `0.0.0.0:5000`.

### Run the Client
```bash
cd client
python3 client.py
```
- Register a new user (a token will be auto-generated).
- Login using username, password, and the stored token.

---

## Docker Setup
### Build & Start
```bash
docker-compose build
docker-compose up
```
This starts:
- **Server container** (runs `server.py`).

### Access Logs
```bash
docker logs secure_login_server
```

### Open Shell
```bash
docker exec -it secure_login_server bash
```

---

## Security Design
- **AES-CBC** with unique IV for each encryption.
- **Diffie-Hellman Key Exchange** ensures secure AES key generation.
- **bcrypt Hashing** for passwords and MAC addresses.
- **30-day Token Authentication**.
- **SQLite Database** for user credentials and tokens.

---

## Future Enhancements
- Admin panel for managing users (token extension, MAC reset).
- Blockchain-based audit trail for tamper-proof logs.
- Two-Factor Authentication (2FA).

---

## License
This project is for educational purposes only.

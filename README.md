# Secure Login System (Debug Version)

## Features
- AES + Diffie-Hellman for secure password transfer.
- Strong password validation (8 chars, uppercase, number, special).
- Debug logs added for send/receive.
- Each request opens a fresh connection.

## Run Instructions
### Start Server
```
docker-compose up -d --build
docker exec -it secure_login_server /bin/bash
python server.py
```

### Run Client
```
cd client
python client.py
```

import hashlib
import json
import os
from datetime import datetime

BLOCKCHAIN_FILE = 'blockchain.json'

def calculate_hash(block):
    block_str = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(block_str).hexdigest()

def create_block(index, username, gps, mac, status, previous_hash):
    block = {
        'index': index,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'username': username,
        'gps': gps,
        'mac': mac,
        'status': status,
        'previous_hash': previous_hash
    }
    block['hash'] = calculate_hash(block)
    return block

def load_chain():
    if not os.path.exists(BLOCKCHAIN_FILE):
        return []
    with open(BLOCKCHAIN_FILE, 'r') as f:
        return json.load(f)

def save_chain(chain):
    with open(BLOCKCHAIN_FILE, 'w') as f:
        json.dump(chain, f, indent=4)

def add_login_attempt(username, gps, mac, status):
    chain = load_chain()
    previous_hash = chain[-1]['hash'] if chain else '0'
    new_block = create_block(len(chain) + 1, username, gps, mac, status, previous_hash)
    chain.append(new_block)
    save_chain(chain)

def verify_chain():
    chain = load_chain()
    for i in range(1, len(chain)):
        if chain[i]['previous_hash'] != chain[i-1]['hash']:
            return False
        if chain[i]['hash'] != calculate_hash({k: chain[i][k] for k in chain[i] if k != 'hash'}):
            return False
    return True

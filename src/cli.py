#!/usr/bin/env python3
import argparse, os, json
from src import crypto, db, audit
from pathlib import Path

def register(username):
    db.init_db()
    sk, pk = crypto.generate_x25519_keypair()
    sk_raw = crypto.x25519_private_bytes(sk)
    pk_raw = crypto.x25519_public_bytes(pk)
    conn = db.get_conn(); c = conn.cursor()
    c.execute("INSERT INTO users (username, public_key, private_key_encrypted) VALUES (?, ?, ?)", (username, pk_raw, sk_raw))
    conn.commit(); conn.close()
    audit.add_audit('register', {'user': username})
    print(f"Registered {username}")

def initdb():
    db.init_db(); print('db initialized')

if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--initdb', action='store_true')
    parser.add_argument('--register')
    args = parser.parse_args()
    if args.initdb: initdb()
    if args.register: register(args.register)

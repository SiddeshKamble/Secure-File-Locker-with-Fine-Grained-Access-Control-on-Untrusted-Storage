import sqlite3, os
from pathlib import Path
DB_PATH = os.environ.get('SFL_DB', str(Path(__file__).parent / 'sfl.db'))

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE,
                 public_key BLOB,
                 private_key_encrypted BLOB
                 )''')
    c.execute('''CREATE TABLE IF NOT EXISTS files (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 owner_id INTEGER,
                 filename TEXT,
                 ciphertext_path TEXT,
                 file_key_wrapped TEXT,
                 metadata TEXT
                 )''')
    c.execute('''CREATE TABLE IF NOT EXISTS acl (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 file_id INTEGER,
                 grantee_username TEXT,
                 wrapped_key BLOB,
                 role TEXT
                 )''')
    c.execute('''CREATE TABLE IF NOT EXISTS auditlog (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 entry_hash TEXT,
                 prev_hash TEXT,
                 timestamp TEXT,
                 action TEXT,
                 details TEXT
                 )''')
    conn.commit()
    conn.close()

def get_conn():
    return sqlite3.connect(DB_PATH)

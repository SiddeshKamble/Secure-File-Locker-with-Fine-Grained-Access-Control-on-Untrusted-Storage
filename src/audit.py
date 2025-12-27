import hashlib, json, datetime
from src.db import get_conn

def add_audit(action: str, details: dict):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT entry_hash FROM auditlog ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    prev = row[0] if row else ''
    payload = dict(timestamp=str(datetime.datetime.utcnow()), action=action, details=details)
    payload_json = json.dumps(payload, sort_keys=True)
    entry_hash = hashlib.sha256((prev + payload_json).encode()).hexdigest()
    c.execute("INSERT INTO auditlog (entry_hash, prev_hash, timestamp, action, details) VALUES (?, ?, ?, ?, ?)",
              (entry_hash, prev, payload['timestamp'], action, json.dumps(details)))
    conn.commit()
    conn.close()
    return entry_hash

def verify_chain():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id, entry_hash, prev_hash, timestamp, action, details FROM auditlog ORDER BY id")
    rows = c.fetchall()
    prev = ''
    for r in rows:
        entry_hash = r[1]
        prev_hash = r[2]
        payload = dict(timestamp=r[3], action=r[4], details=json.loads(r[5]))
        payload_json = json.dumps(payload, sort_keys=True)
        expected = hashlib.sha256((prev + payload_json).encode()).hexdigest()
        if expected != entry_hash or prev_hash != prev:
            return False
        prev = entry_hash
    return True

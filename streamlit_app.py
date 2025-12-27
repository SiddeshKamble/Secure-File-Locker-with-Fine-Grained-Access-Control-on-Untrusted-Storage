import streamlit as st
import os, json
from pathlib import Path
import plotly.graph_objects as go
from src.db import init_db, get_conn
from src.crypto import (
    generate_file_key, encrypt_file, decrypt_file,
    wrap_key_with_x25519, unwrap_key_with_x25519,
    generate_x25519_keypair, x25519_private_bytes, x25519_public_bytes
)
from src.audit import add_audit, verify_chain

# Initialize DB
init_db()
st.set_page_config(page_title='Secure File Locker', layout='centered')
st.title('Secure File Locker — Demo UI')

# Session state setup for keys
if 'file_key' not in st.session_state: st.session_state['file_key'] = None
if 'wrapped_key' not in st.session_state: st.session_state['wrapped_key'] = None
if 'unwrapped_key' not in st.session_state: st.session_state['unwrapped_key'] = None

# Helper functions
def get_user_private(username):
    conn = get_conn(); c = conn.cursor()
    c.execute('SELECT private_key_encrypted FROM users WHERE username=?', (username,))
    r = c.fetchone(); conn.close()
    return r[0] if r else None

def get_user_public(username):
    conn = get_conn(); c = conn.cursor()
    c.execute('SELECT public_key FROM users WHERE username=?', (username,))
    r = c.fetchone(); conn.close()
    return r[0] if r else None

# Tabs
tabs = st.tabs(['Register', 'Upload', 'Share', 'Download', 'Revoke', 'Audit','DB Viewer', 'Key Operations'])

# ================= REGISTER TAB =================
with tabs[0]:
    st.header('Register User')
    uname = st.text_input('Username')
    if st.button('Register User'):
        if not uname: st.error('Enter username'); st.stop()
        sk, pk = generate_x25519_keypair()
        conn = get_conn(); c = conn.cursor()
        c.execute(
            'INSERT INTO users (username, public_key, private_key_encrypted) VALUES (?, ?, ?)',
            (uname, x25519_public_bytes(pk), x25519_private_bytes(sk))
        )
        conn.commit(); conn.close()
        add_audit('register', {'user': uname})
        st.success(f'User {uname} registered')

# ================= UPLOAD TAB =================
with tabs[1]:
    st.header('Upload File')
    owner = st.text_input('Owner username (for upload)')
    uploaded = st.file_uploader('Choose file to encrypt')
    if st.button('Upload') and owner and uploaded:
        data = uploaded.read(); filename = uploaded.name
        key = generate_file_key(); ciphertext = encrypt_file(key, data)
        os.makedirs('storage', exist_ok=True)
        path = f'storage/{filename}'; open(path,'wb').write(ciphertext)
        owner_pub = get_user_public(owner)
        if not owner_pub: st.error('Owner not found')
        else:
            wrapped = wrap_key_with_x25519(owner_pub, key)
            conn = get_conn(); c = conn.cursor()
            c.execute(
                "INSERT INTO files (owner_id, filename, ciphertext_path, file_key_wrapped, metadata) VALUES ((SELECT id FROM users WHERE username=?), ?, ?, ?, '{}')",
                (owner, filename, path, json.dumps({owner: wrapped.hex()}))
            )
            conn.commit(); conn.close()
            add_audit('upload', {'owner': owner, 'file': filename})
            st.success(f'Uploaded {filename}')

# ================= SHARE TAB =================
with tabs[2]:
    st.header('Share File')
    owner = st.text_input('Owner username (share)')
    target = st.text_input('Target username (grant)')
    fname = st.text_input('Filename to share')
    if st.button('Share'):
        conn = get_conn(); c = conn.cursor()
        c.execute('SELECT id, file_key_wrapped FROM files WHERE filename=?', (fname,))
        r = c.fetchone()
        if not r: st.error('File not found'); st.stop()
        file_id, wrapped_json = r[0], json.loads(r[1])
        if owner not in wrapped_json: st.error('Owner has no wrapped entry'); st.stop()
        owner_priv = get_user_private(owner)
        key = unwrap_key_with_x25519(owner_priv, bytes.fromhex(wrapped_json[owner]))
        target_pub = get_user_public(target)
        if not target_pub: st.error('Target not found'); st.stop()
        twrap = wrap_key_with_x25519(target_pub, key); wrapped_json[target] = twrap.hex()
        c.execute('UPDATE files SET file_key_wrapped=? WHERE id=?', (json.dumps(wrapped_json), file_id)); conn.commit(); conn.close()
        add_audit('share', {'owner': owner, 'target': target, 'file': fname})
        st.success(f'Granted access to {target}')

# ================= DOWNLOAD TAB =================
with tabs[3]:
    st.header('Download File')
    user = st.text_input('Username (download)')
    fname = st.text_input('Filename to download')
    if st.button('Download'):
        conn = get_conn(); c = conn.cursor()
        c.execute('SELECT ciphertext_path, file_key_wrapped FROM files WHERE filename=?', (fname,))
        r = c.fetchone()
        if not r: st.error('File not found'); st.stop()
        path, wrapped_json = r[0], json.loads(r[1])
        if user not in wrapped_json: st.error('No access'); st.stop()
        user_priv = get_user_private(user)
        key = unwrap_key_with_x25519(user_priv, bytes.fromhex(wrapped_json[user]))
        ciphertext = open(path,'rb').read(); plaintext = decrypt_file(key, ciphertext)
        add_audit('download', {'user': user, 'file': fname})
        st.download_button('Download decrypted file', plaintext, file_name=fname)

# ================= REVOKE TAB =================
with tabs[4]:
    st.header('Revoke Access')
    owner = st.text_input('Owner (revoke)')
    target = st.text_input('User to revoke')
    fname = st.text_input('Filename')
    if st.button('Revoke'):
        conn = get_conn(); c = conn.cursor()
        c.execute('SELECT id, file_key_wrapped FROM files WHERE filename=?', (fname,))
        r = c.fetchone()
        if not r: st.error('File not found'); st.stop()
        file_id, wrapped_json = r[0], json.loads(r[1])
        if target not in wrapped_json: st.warning('Target had no access')
        else:
            del wrapped_json[target]
            c.execute('UPDATE files SET file_key_wrapped=? WHERE id=?', (json.dumps(wrapped_json), file_id)); conn.commit(); conn.close()
            add_audit('revoke', {'owner': owner, 'target': target, 'file': fname})
            st.success(f'Revoked {target}')

# ================= AUDIT TAB =================
with tabs[5]:
    st.header('Audit Log')
    conn = get_conn(); c = conn.cursor()
    c.execute('SELECT timestamp, action, details FROM auditlog ORDER BY id DESC')
    rows = c.fetchall(); conn.close()
    if rows:
        import pandas as pd
        df = pd.DataFrame(rows, columns=["Timestamp", "Action", "Details"])
        st.dataframe(df)
    if st.button('Verify Chain'):
        if verify_chain(): st.success('Audit chain OK')
        else: st.error('Audit chain INVALID')

# ================= DB VIEWER TAB =================
with tabs[6]:
    st.header("Database Viewer")
    conn = get_conn(); c = conn.cursor()
    tables = ["users", "files", "acl", "auditlog"]
    choice = st.selectbox("Select table", tables)
    if st.button("Load Table"):
        rows = c.execute(f"SELECT * FROM {choice}").fetchall()
        st.write(f"{len(rows)} rows found in '{choice}' table:")
        st.dataframe(rows)
    conn.close()

# ================= KEY OPERATIONS TAB =================
with tabs[7]:
    st.header("Key Encryption & Decryption Demo")

    # Step 1: Generate a file key
    if st.button("Generate File Key"):
        st.session_state['file_key'] = generate_file_key()
        st.code(st.session_state['file_key'].hex(), language='text')
        st.success("File key generated!")

    # Step 2: Wrap key
    username_wrap = st.text_input("Enter username to wrap key for")
    if st.button("Wrap Key") and st.session_state['file_key']:
        pub = get_user_public(username_wrap)
        if not pub: st.error("User not found")
        else:
            st.session_state['wrapped_key'] = wrap_key_with_x25519(pub, st.session_state['file_key'])
            st.code(st.session_state['wrapped_key'].hex(), language='text')
            st.success(f"Key wrapped for {username_wrap}")

    # Step 3: Unwrap key
    username_unwrap = st.text_input("Enter username to unwrap key for")
    if st.button("Unwrap Key") and st.session_state['wrapped_key']:
        priv = get_user_private(username_unwrap)
        if not priv: st.error("User not found")
        else:
            st.session_state['unwrapped_key'] = unwrap_key_with_x25519(priv, st.session_state['wrapped_key'])
            st.code(st.session_state['unwrapped_key'].hex(), language='text')
            st.success(f"Key unwrapped for {username_unwrap}")

    # Step 4: Compare keys
    if st.session_state['file_key'] and st.session_state['unwrapped_key']:
        match = st.session_state['file_key'] == st.session_state['unwrapped_key']
        st.info(f"Keys match: {'✅ Yes' if match else '❌ No'}")

    # Step 5: Visual key flow
    if st.session_state['file_key']:
        nodes = ["File Key"]
        node_colors = ["lightblue"]
        if st.session_state['wrapped_key']: nodes.append("Wrapped Key"); node_colors.append("orange")
        if st.session_state['unwrapped_key']: nodes.append("Unwrapped Key"); node_colors.append("lightgreen")

        fig = go.Figure(go.Sankey(
            node=dict(pad=15, thickness=20, line=dict(color="black", width=0.5), label=nodes, color=node_colors),
            link=dict(source=[0,1][:len(nodes)-1], target=[1,2][:len(nodes)-1], value=[1]*(len(nodes)-1), color="gray")
        ))
        st.plotly_chart(fig, use_container_width=True)

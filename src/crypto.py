from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import x25519, rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os

def generate_file_key():
    return AESGCM.generate_key(bit_length=256)

def encrypt_file(key: bytes, plaintext: bytes, associated_data: bytes = None):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ct

def decrypt_file(key: bytes, ciphertext: bytes, associated_data: bytes = None):
    aesgcm = AESGCM(key)
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    return aesgcm.decrypt(nonce, ct, associated_data)

def generate_x25519_keypair():
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key()
    return sk, pk

def x25519_public_bytes(pub):
    return pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

def x25519_private_bytes(priv):
    return priv.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())

def wrap_key_with_x25519(recipient_public_raw: bytes, key_to_wrap: bytes):
    recipient_pub = x25519.X25519PublicKey.from_public_bytes(recipient_public_raw)
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key()
    shared = eph_priv.exchange(recipient_pub)
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'file-locker-wrap').derive(shared)
    aesgcm = AESGCM(derived)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, key_to_wrap, None)
    return eph_pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw) + nonce + ct

def unwrap_key_with_x25519(recipient_private_raw: bytes, wrapped: bytes):
    eph_pub_raw = wrapped[:32]
    nonce = wrapped[32:44]
    ct = wrapped[44:]
    recipient_priv = x25519.X25519PrivateKey.from_private_bytes(recipient_private_raw)
    eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pub_raw)
    shared = recipient_priv.exchange(eph_pub)
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'file-locker-wrap').derive(shared)
    aesgcm = AESGCM(derived)
    key = aesgcm.decrypt(nonce, ct, None)
    return key

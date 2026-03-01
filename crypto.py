from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64

def generate_keys():
    """Génère une paire de clés RSA (2048 bits)"""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def hash_data(data):
    """Calcule le hash SHA256 de données binaires"""
    if isinstance(data, str):
        data = data.encode()
    h = SHA256.new(data)
    return h.hexdigest()

def sign_data(data, private_key):
    """Signe des données avec la clé privée"""
    key = RSA.import_key(private_key)
    h = SHA256.new(data)
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode()

def verify_signature(data, signature, public_key):
    """Vérifie une signature avec la clé publique"""
    try:
        key = RSA.import_key(public_key)
        h = SHA256.new(data)
        pkcs1_15.new(key).verify(h, base64.b64decode(signature))
        return True
    except (ValueError, TypeError, Exception):
        return False

def encrypt_file(data, key=None):
    """Chiffre des données avec AES-256 GCM"""
    if key is None:
        key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, key, cipher.nonce, tag

def decrypt_file(ciphertext, key, nonce, tag):
    """Déchiffre des données avec AES-256 GCM"""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
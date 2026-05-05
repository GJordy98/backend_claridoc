import os
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def generate_aes_credentials():
    """Génère une clé AES-256 et un IV aléatoires au format Hex."""
    key = os.urandom(32)
    iv = os.urandom(16)
    return key.hex().upper(), iv.hex().upper()

def encrypt_license_data(payload_dict, aes_key_hex, iv_hex):
    """
    Chiffre un dictionnaire JSON avec AES-256-CBC et PKCS7 padding.
    Compatible avec le CryptoManager de l'application C# ClariDoc.
    """
    key = bytes.fromhex(aes_key_hex)
    iv = bytes.fromhex(iv_hex)
    
    # Préparer les données
    payload_str = json.dumps(payload_dict)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(payload_str.encode('utf-8')) + padder.finalize()
    
    # Chiffrer
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_bytes = encryptor.update(padded_data) + encryptor.finalize()
    
    # Retourner en Base64
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def decrypt_license_data(encrypted_base64, aes_key_hex, iv_hex):
    """
    Déchiffre la licence (utile pour les tests backend).
    """
    key = bytes.fromhex(aes_key_hex)
    iv = bytes.fromhex(iv_hex)
    encrypted_bytes = base64.b64decode(encrypted_base64)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_bytes) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return json.loads(data.decode('utf-8'))
def encrypt_simple_string(text, aes_key_hex, iv_hex):
    """
    Chiffre une simple chaîne (sans JSON) avec AES-256-CBC.
    Idéal pour les mots de passe FTP.
    """
    key = bytes.fromhex(aes_key_hex)
    iv = bytes.fromhex(iv_hex)
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode('utf-8')) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_bytes = encryptor.update(padded_data) + encryptor.finalize()
    
    return base64.b64encode(encrypted_bytes).decode('utf-8')

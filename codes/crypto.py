import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15

# --- Key Management Functions ---

def generate_key_pair(bits=2048):
    """Generates a new RSA public/private key pair."""
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def import_private_key(key_data):
    """Imports a private key from a byte string."""
    return RSA.import_key(key_data)

def import_public_key(key_data):
    """Imports a public key from a byte string."""
    return RSA.import_key(key_data)

# --- Encryption and Decryption Functions ---

def encrypt_message(message, recipient_public_key):
    """Encrypts a message using a combination of AES and RSA."""
    recipient_key = import_public_key(recipient_public_key)
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)
    cipher_aes = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
    return encrypted_session_key, cipher_aes.nonce, ciphertext, tag

def decrypt_message(encrypted_session_key, nonce, ciphertext, tag, private_key):
    """Decrypts a message using the user's private key."""
    private_key = import_private_key(private_key)
    try:
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(encrypted_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')
    except (ValueError, KeyError) as e:
        print(f"Decryption failed: {e}")
        return None

# --- Authentication and Integrity Functions ---

def sign_message(message, private_key):
    """Signs a message using the sender's private key."""
    private_key = import_private_key(private_key)
    h = SHA256.new(message.encode('utf-8'))
    signer = pkcs1_15.new(private_key)
    signature = signer.sign(h)
    return signature

def verify_signature(message, signature, sender_public_key):
    """Verifies the digital signature of a message."""
    sender_key = import_public_key(sender_public_key)
    h = SHA256.new(message.encode('utf-8'))
    verifier = pkcs1_15.new(sender_key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
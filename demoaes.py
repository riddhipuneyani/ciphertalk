from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Step 1: Generate a random 16-byte AES key
key = get_random_bytes(16)

# Step 2: Create AES cipher (using EAX mode for security)
cipher = AES.new(key, AES.MODE_EAX)

# Step 3: Encrypt a sample message
message = "Hello Secure World!"
ciphertext, tag = cipher.encrypt_and_digest(message.encode())

# Step 4: Save nonce (needed for decryption)
nonce = cipher.nonce

print("Original Message:", message)
print("Encrypted (base64):", base64.b64encode(ciphertext).decode())

# Step 5: Decrypt
cipher_dec = AES.new(key, AES.MODE_EAX, nonce=nonce)
plaintext = cipher_dec.decrypt(ciphertext).decode()

print("Decrypted:", plaintext)

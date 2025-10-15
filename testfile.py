import crypto as cu

# Step 1: Generate RSA keypair for receiver
private_key, public_key = cu.generate_rsa_keypair()

# Step 2: Sender generates AES key
aes_key = cu.generate_aes_key()
print("AES Key (base64):", cu.b64encode(aes_key))

# Step 3: Encrypt AES key with receiver's public key
enc_aes_key = cu.encrypt_aes_key_with_rsa(aes_key, public_key)

# Step 4: Receiver decrypts AES key
dec_aes_key = cu.decrypt_aes_key_with_rsa(enc_aes_key, private_key)
print("Decrypted AES Key (base64):", cu.b64encode(dec_aes_key))

# Step 5: Encrypt a message with AES
message = "Hello from Secure Messaging!"
ciphertext, nonce, tag = cu.encrypt_message(message, aes_key)

print("\nOriginal:", message)
print("Ciphertext (base64):", cu.b64encode(ciphertext))

# Step 6: Decrypt message with AES
decrypted = cu.decrypt_message(ciphertext, dec_aes_key, nonce, tag)
print("Decrypted:", decrypted)

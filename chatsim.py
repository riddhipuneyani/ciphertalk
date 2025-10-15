import crypto as cu

# ----- Setup: Generate RSA keys for User A and User B -----
A_private, A_public = cu.generate_rsa_keypair()
B_private, B_public = cu.generate_rsa_keypair()

print("User A and User B have generated their RSA keys.")

# ----- Step 1: User A wants to send a secure message to User B -----
# A creates an AES session key
aes_key = cu.generate_aes_key()

# A encrypts the AES key with B's public RSA key
enc_aes_key = cu.encrypt_aes_key_with_rsa(aes_key, B_public)

# This encrypted AES key will be sent to B (safe to send)
print("\n[User A → User B] Sending encrypted AES key.")

# ----- Step 2: User B receives it and decrypts with their private key -----
dec_aes_key = cu.decrypt_aes_key_with_rsa(enc_aes_key, B_private)

print("[User B] Decrypted AES key received successfully!")

# ----- Step 3: User A encrypts a message with AES key -----
message_A = "Hello B, this is A. Are you receiving securely?"
ciphertext, nonce, tag = cu.encrypt_message(message_A, aes_key)

print("\n[User A] Sending encrypted message:", cu.b64encode(ciphertext))

# ----- Step 4: User B decrypts the message -----
decrypted_B = cu.decrypt_message(ciphertext, dec_aes_key, nonce, tag)

print("[User B] Decrypted message:", decrypted_B)

import crypto as cu

# ---------------- RSA Key Generation ----------------
A_private, A_public = cu.generate_rsa_keypair()
B_private, B_public = cu.generate_rsa_keypair()

print("RSA keys generated for User A and User B.\n")

# ---------------- AES Session Key Exchange ----------------
# User A creates AES session key
aes_key = cu.generate_aes_key()

# Encrypt AES key with B's public key
enc_aes_key = cu.encrypt_aes_key_with_rsa(aes_key, B_public)

# B decrypts AES key using private key
dec_aes_key = cu.decrypt_aes_key_with_rsa(enc_aes_key, B_private)
print("[Key Exchange] AES key securely shared from A → B\n")

# ---------------- Chat Simulation ----------------
while True:
    # User A sends message
    msg_A = input("User A: ")
    if msg_A.lower() == "exit":
        break
    ciphertext, nonce, tag = cu.encrypt_message(msg_A, aes_key)

    # Simulate sending message to B
    decrypted_B = cu.decrypt_message(ciphertext, dec_aes_key, nonce, tag)
    print("User B received (decrypted):", decrypted_B)

    # User B replies
    msg_B = input("User B: ")
    if msg_B.lower() == "exit":
        break
    ciphertext_B, nonce_B, tag_B = cu.encrypt_message(msg_B, dec_aes_key)

    # Simulate sending message to A
    decrypted_A = cu.decrypt_message(ciphertext_B, aes_key, nonce_B, tag_B)
    print("User A received (decrypted):", decrypted_A)

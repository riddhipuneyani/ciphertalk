import socket
import json
import base64
import os
import threading
import time

# --- PROJECT MODULE IMPORTS ---
# Ensure crypto_utils.py and ai_utils.py are in the same directory
from crypto import generate_key_pair, encrypt_message, decrypt_message, sign_message, verify_signature
from ai import voice_to_text, summarize_text

# --- GLOBAL VARIABLES ---
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432
MY_USERNAME = ""
my_private_key = None
my_public_key = None

# Thread-safe state management
public_key_cache = {}
cache_lock = threading.Lock()
key_available = threading.Condition(cache_lock)

# Conversation state
current_recipient = None
last_received_message = ""
conversation_history = {}  # Stores {username: [message1, message2, ...]}


# --- KEY MANAGEMENT FUNCTIONS (Unchanged) ---

def save_keys(private_key, public_key, username):
    """Saves keys locally."""
    with open(f"{username}_private.pem", "wb") as f:
        f.write(private_key)
    with open(f"{username}_public.pem", "wb") as f:
        f.write(public_key)


def load_keys(username):
    """Loads keys from local storage."""
    try:
        with open(f"{username}_private.pem", "rb") as f:
            private_key = f.read()
        with open(f"{username}_public.pem", "rb") as f:
            public_key = f.read()
        return private_key, public_key
    except FileNotFoundError:
        return None, None


def register_user(sock):
    """Handles user registration and key generation."""
    global MY_USERNAME, my_private_key, my_public_key
    MY_USERNAME = input("Enter a username: ")

    my_private_key, my_public_key = load_keys(MY_USERNAME)

    if not my_private_key:
        print("Generating new key pair...")
        my_private_key, my_public_key = generate_key_pair()
        save_keys(my_private_key, my_public_key, MY_USERNAME)

    data = {
        "type": "register",
        "username": MY_USERNAME,
        "public_key": base64.b64encode(my_public_key).decode('utf-8')
    }
    sock.sendall(json.dumps(data).encode('utf-8'))
    print("Registration request sent. Waiting for server confirmation...")


def get_recipient_public_key(sock, recipient):
    """
    Requests a recipient's public key and waits for it to be cached by the listener.
    """
    with cache_lock:
        if recipient in public_key_cache:
            return public_key_cache[recipient]

        print(f"Requesting public key for {recipient}...")
        data = {
            "type": "get_key",
            "recipient": recipient
        }
        sock.sendall(json.dumps(data).encode('utf-8'))

        key_available.wait(5)

        if recipient in public_key_cache:
            return public_key_cache[recipient]
        else:
            return None


# --- MESSAGING FUNCTIONS (Unchanged) ---

def send_message(sock, recipient, message_content):
    """Encrypts, signs, and sends a message."""
    recipient_public_key = get_recipient_public_key(sock, recipient)
    if not recipient_public_key:
        print("Could not get recipient's public key. Message not sent.")
        return

    signature = sign_message(message_content, my_private_key)
    encrypted_session_key, nonce, ciphertext, tag = encrypt_message(message_content, recipient_public_key)

    encrypted_message = {
        "type": "send_message",
        "sender": MY_USERNAME,
        "recipient": recipient,
        "content": {
            "session_key": base64.b64encode(encrypted_session_key).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8')
        },
        "signature": base64.b64encode(signature).decode('utf-8')
    }

    sock.sendall(json.dumps(encrypted_message).encode('utf-8'))
    print(f"Message sent to {recipient}.")


def listen_for_messages(sock):
    """Listens for all incoming data from the server."""
    global last_received_message, conversation_history

    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print("Server disconnected.")
                break

            try:
                message = json.loads(data.decode('utf-8'))

                # New Message Handling
                if message['type'] == 'new_message':
                    sender = message['sender']
                    content = message['content']  # <<< CRITICAL: content is defined here
                    signature = base64.b64decode(message['signature'])

                    # Decrypt the message content
                    decrypted_message = decrypt_message(
                        base64.b64decode(content['session_key']),
                        base64.b64decode(content['nonce']),
                        base64.b64decode(content['ciphertext']),
                        base64.b64decode(content['tag']),
                        my_private_key
                    )

                    if decrypted_message:
                        # Update history and last message
                        if sender not in conversation_history:
                            conversation_history[sender] = []
                        conversation_history[sender].append(decrypted_message)
                        last_received_message = decrypted_message

                        # Verification check
                        with cache_lock:
                            sender_key = public_key_cache.get(sender)

                        if sender_key and verify_signature(decrypted_message, signature, sender_key):
                            print(f"\n[{sender}]: {decrypted_message}")
                        else:
                            # Display message with unverified warning
                            print(f"\n[UNVERIFIED MESSAGE from {sender}]: {decrypted_message}")

                            # If key is missing, automatically request it in background
                            if not sender_key:
                                print(f"[INFO]: Public key for {sender} not found. Automatically requesting it...")
                                data_req = {"type": "get_key", "recipient": sender}
                                sock.sendall(json.dumps(data_req).encode('utf-8'))

                    else:
                        print(f"\n[ERROR] Failed to decrypt message from {sender}.")

                # Server Status Handling
                elif message['type'] == 'status':
                    print(f"\nServer Status: {message['message']}")

                # Key Response Handling
                elif message['type'] == 'public_key_response':
                    if message['status'] == 'success':
                        recipient_name = message['recipient']
                        public_key = base64.b64decode(message['public_key'])
                        with cache_lock:
                            public_key_cache[recipient_name] = public_key
                            key_available.notify_all()
                        print(f"\n[INFO]: Public key for {recipient_name} successfully cached.")
                    else:
                        print(f"Error getting public key for {message['recipient']}: {message['message']}")

            except json.JSONDecodeError:
                print(f"Received malformed JSON: {data.decode('utf-8')}")

        except socket.error as e:
            print(f"Connection to server lost: {e}")
            break


# --- MAIN EXECUTION ---

def main():
    global current_recipient, last_received_message
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((SERVER_HOST, SERVER_PORT))
            register_user(sock)

            listener_thread = threading.Thread(target=listen_for_messages, args=(sock,), daemon=True)
            listener_thread.start()

            time.sleep(1)

            print("\nCommands: 'set <username>' | 'voice' | 'summarize' | 'exit'")
            while True:
                user_input = input(f"\n({MY_USERNAME} -> {current_recipient or '??'}): ")

                if user_input.lower() == 'exit':
                    break

                if user_input.lower().startswith("set "):
                    new_recipient = user_input.split(" ", 1)[1].strip()
                    if new_recipient:
                        current_recipient = new_recipient
                        print(f"Conversation set to {current_recipient}.")
                    else:
                        print("Invalid 'set' command. Usage: set <username>")
                    continue

                if user_input.lower() == 'voice':
                    # --- AI Feature: Voice-to-Text ---
                    if not current_recipient:
                        print("Please set a recipient first using 'set <username>'.")
                        continue

                    text_input = voice_to_text()
                    if text_input:
                        print(f"VOICE CONVERTED: \"{text_input}\"")
                        send_message(sock, current_recipient, text_input)
                    else:
                        print("Voice message sending cancelled or failed.")
                    continue

                if user_input.lower() == 'summarize':
                    # --- AI Feature: Text Summarization ---
                    if not last_received_message:
                        print("Cannot summarize: No message has been received yet in this session.")
                        continue

                    print(f"Summarizing last received message (from {last_received_message[:35]}...):")
                    summary = summarize_text(last_received_message)
                    print(f"\n--- Message Summary ---\n{summary}\n-----------------------")
                    continue

                if not current_recipient:
                    print("Please set a recipient first using 'set <username>'.")
                    continue

                # Default case: send the message
                message_content = user_input
                send_message(sock, current_recipient, message_content)
                time.sleep(0.1)

        # The corrected indentation for the outermost exception handler
        except socket.error as e:
            print(f"Could not connect to server: {e}")


if __name__ == "__main__":
    main()
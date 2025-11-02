import socket
import threading
import json
import base64

HOST = '127.0.0.1'
PORT = 65432

PUBLIC_KEYS = {}
CONNECTED_CLIENTS = {}


def handle_client(conn, addr):
    print(f"Connected by {addr}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            try:
                message = json.loads(data.decode('utf-8'))
            except json.JSONDecodeError:
                print(f"Received malformed JSON from {addr}")
                continue

            if message['type'] == 'register':
                username = message['username']
                public_key_b64 = message['public_key']
                PUBLIC_KEYS[username] = {"public_key": base64.b64decode(public_key_b64), "connection": conn}
                CONNECTED_CLIENTS[username] = conn
                print(f"User {username} registered and connected.")
                response = {"type": "status", "status": "success", "message": "Registration successful."}
                conn.sendall(json.dumps(response).encode('utf-8'))

            elif message['type'] == 'get_key':
                recipient = message['recipient']
                if recipient in PUBLIC_KEYS:
                    recipient_key_b64 = base64.b64encode(PUBLIC_KEYS[recipient]['public_key']).decode('utf-8')
                    response = {"type": "public_key_response", "status": "success", "recipient": recipient,
                                "public_key": recipient_key_b64}
                    conn.sendall(json.dumps(response).encode('utf-8'))
                else:
                    # Consistent response format, even on failure
                    response = {"type": "public_key_response", "status": "error", "recipient": recipient,
                                "message": "Recipient not found."}
                    conn.sendall(json.dumps(response).encode('utf-8'))

            elif message['type'] == 'send_message':
                recipient = message['recipient']
                if recipient in CONNECTED_CLIENTS:
                    recipient_conn = CONNECTED_CLIENTS[recipient]
                    forward_message = {
                        "type": "new_message",
                        "sender": message['sender'],
                        "content": message['content'],
                        "signature": message['signature']
                    }
                    recipient_conn.sendall(json.dumps(forward_message).encode('utf-8'))
                    print(f"Message from {message['sender']} relayed to {recipient}.")
                    response = {"type": "status", "status": "success", "message": "Message sent."}
                    conn.sendall(json.dumps(response).encode('utf-8'))
                else:
                    response = {"type": "status", "status": "error", "message": "Recipient is offline."}
                    conn.sendall(json.dumps(response).encode('utf-8'))

            else:
                print(f"Unknown message type from {addr}: {message.get('type', 'N/A')}")
                response = {"type": "status", "status": "error", "message": "Unknown message type."}
                conn.sendall(json.dumps(response).encode('utf-8'))

    except (socket.error, json.JSONDecodeError, KeyError) as e:
        print(f"Error with client {addr}: {e}")
    finally:
        print(f"Client {addr} disconnected.")
        for username, data in list(PUBLIC_KEYS.items()):
            if 'connection' in data and data['connection'] == conn:
                del PUBLIC_KEYS[username]
        for username, connection in list(CONNECTED_CLIENTS.items()):
            if connection == conn:
                del CONNECTED_CLIENTS[username]
        conn.close()


def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()


if __name__ == "__main__":
    start_server()
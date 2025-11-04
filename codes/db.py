import sqlite3
import json

DB_NAME = 'ciphertalk.db'

def init_db():

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id TEXT PRIMARY KEY,
                  timestamp TEXT,
                  sender TEXT,
                  recipient TEXT,
                  message_text TEXT,
                  encrypted_content TEXT,
                  signature TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS encryptions
                 (id TEXT PRIMARY KEY,
                  timestamp TEXT,
                  sender TEXT,
                  recipient TEXT,
                  encryption_type TEXT,
                  encryption_time_ms REAL,
                  message_size_bytes INTEGER,
                  session_key_encrypted TEXT,
                  nonce TEXT,
                  ciphertext TEXT,
                  tag TEXT,
                  signature TEXT)''')
    conn.commit()
    conn.close()

def save_message(message_obj):

    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''INSERT OR REPLACE INTO messages
                     (id, timestamp, sender, recipient, message_text, encrypted_content, signature)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (message_obj['id'],
                   message_obj['timestamp'],
                   message_obj['sender'],
                   message_obj['recipient'],
                   message_obj.get('message'),
                   json.dumps(message_obj.get('encrypted_content', {})),
                   message_obj.get('signature')))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] save_message error: {e}")

def save_encryption(enc_obj):

    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''INSERT OR REPLACE INTO encryptions
                     (id, timestamp, sender, recipient, encryption_type, encryption_time_ms,
                      message_size_bytes, session_key_encrypted, nonce, ciphertext, tag, signature)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (enc_obj['id'], enc_obj['timestamp'], enc_obj['sender'], enc_obj['recipient'],
                   enc_obj.get('encryption_type', 'RSA-AES-GCM'), enc_obj.get('encryption_time_ms', 0),
                   enc_obj.get('message_size_bytes', 0), enc_obj.get('session_key_encrypted', ''),
                   enc_obj.get('nonce', ''), enc_obj.get('ciphertext', ''), enc_obj.get('tag', ''),
                   enc_obj.get('signature', '')))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] save_encryption error: {e}")

def load_user_messages(current_user: str):

    items = []
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''SELECT id,timestamp,sender,recipient,message_text,encrypted_content,signature
                     FROM messages
                     WHERE sender=? OR recipient=?
                     ORDER BY timestamp''', (current_user, current_user))
        rows = c.fetchall()
        for r in rows:
            items.append({
                'id': r[0], 'timestamp': r[1], 'sender': r[2], 'recipient': r[3],
                'message': r[4],
                'encrypted_content': json.loads(r[5]) if r[5] else {},
                'signature': r[6]
            })
        conn.close()
    except Exception as e:
        print(f"[DB] load_user_messages error: {e}")
    return items

def load_user_encryptions(current_user: str):

    items = []
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''SELECT id,timestamp,sender,recipient,encryption_type,encryption_time_ms,
                            message_size_bytes,session_key_encrypted,nonce,ciphertext,tag,signature
                     FROM encryptions
                     WHERE sender=? OR recipient=?
                     ORDER BY timestamp''', (current_user, current_user))
        rows = c.fetchall()
        for r in rows:
            items.append({
                'id': r[0], 'timestamp': r[1], 'sender': r[2], 'recipient': r[3],
                'encryption_type': r[4], 'encryption_time_ms': r[5], 'message_size_bytes': r[6],
                'session_key_encrypted': r[7], 'nonce': r[8], 'ciphertext': r[9], 'tag': r[10], 'signature': r[11]
            })
        conn.close()
    except Exception as e:
        print(f"[DB] load_user_encryptions error: {e}")
    return items

def load_all_messages():

    items = []
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('SELECT id,timestamp,sender,recipient,message_text,encrypted_content,signature FROM messages ORDER BY timestamp')
        rows = c.fetchall()
        for r in rows:
            items.append({
                'id': r[0], 'timestamp': r[1], 'sender': r[2], 'recipient': r[3],
                'message': r[4], 'encrypted_content': json.loads(r[5]) if r[5] else {}, 'signature': r[6]
            })
        conn.close()
    except Exception as e:
        print(f"[DB] load_all_messages error: {e}")
    return items

def load_all_encryptions():

    items = []
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''SELECT id,timestamp,sender,recipient,encryption_type,encryption_time_ms,
                            message_size_bytes,session_key_encrypted,nonce,ciphertext,tag,signature
                     FROM encryptions ORDER BY timestamp''')
        rows = c.fetchall()
        for r in rows:
            items.append({
                'id': r[0], 'timestamp': r[1], 'sender': r[2], 'recipient': r[3],
                'encryption_type': r[4], 'encryption_time_ms': r[5], 'message_size_bytes': r[6],
                'session_key_encrypted': r[7], 'nonce': r[8], 'ciphertext': r[9], 'tag': r[10], 'signature': r[11]
            })
        conn.close()
    except Exception as e:
        print(f"[DB] load_all_encryptions error: {e}")
    return items

def get_user_stats(current_user: str):

    stats = {'total_messages': 0, 'total_encryptions': 0}
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM messages WHERE sender=? OR recipient=?', (current_user, current_user))
        stats['total_messages'] = c.fetchone()[0] or 0
        c.execute('SELECT COUNT(*) FROM encryptions WHERE sender=? OR recipient=?', (current_user, current_user))
        stats['total_encryptions'] = c.fetchone()[0] or 0
        conn.close()
    except Exception as e:
        print(f"[DB] get_user_stats error: {e}")
    return stats



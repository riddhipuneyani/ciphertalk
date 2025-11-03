from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
import threading
import json
import base64
import time
from datetime import datetime
import uuid
from functools import wraps
from collections import defaultdict

from crypto import generate_key_pair, encrypt_message, decrypt_message, sign_message, verify_signature

# Optional AI imports - server will work without them
try:
    from ai import voice_to_text, summarize_text
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    print("Warning: AI features (voice-to-text, summarization) are not available. Install dependencies: pip install speechrecognition spacy vosk pyaudio")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ciphertalk-secret-key-change-in-production'
socketio = SocketIO(app, cors_allowed_origins="*")

# Store active users and their socket connections
active_users = {}  # {username: {'socket_id': id, 'public_key': key}}
messages_store = []  # Store all messages for history
encryptions_log = []  # Store encryption operations
verify_perf_log = []  # Store signature verification timings

# Rate limiting for API calls
api_call_times = {}  # {endpoint: {ip: [timestamps]}}

def rate_limit(max_calls=10, period=60):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            endpoint = request.endpoint
            client_ip = request.remote_addr
            
            now = time.time()
            key = f"{endpoint}:{client_ip}"
            
            if key not in api_call_times:
                api_call_times[key] = []
            
            # Remove old timestamps
            api_call_times[key] = [t for t in api_call_times[key] if now - t < period]
            
            # Check rate limit
            if len(api_call_times[key]) >= max_calls:
                return jsonify({'error': 'Rate limit exceeded. Please slow down.'}), 429
            
            # Add current timestamp
            api_call_times[key].append(now)
            
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Load/save keys helper
def load_keys(username):
    try:
        with open(f"{username}_private.pem", "rb") as f:
            private_key = f.read()
        with open(f"{username}_public.pem", "rb") as f:
            public_key = f.read()
        return private_key, public_key
    except FileNotFoundError:
        return None, None

def save_keys(private_key, public_key, username):
    with open(f"{username}_private.pem", "wb") as f:
        f.write(private_key)
    with open(f"{username}_public.pem", "wb") as f:
        f.write(public_key)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({'error': 'Username required'}), 400
    
    # Generate or load keys
    private_key, public_key = load_keys(username)
    if not private_key:
        print(f"Generating new key pair for {username}...")
        private_key, public_key = generate_key_pair()
        save_keys(private_key, public_key, username)
    
    return jsonify({
        'success': True,
        'username': username,
        'public_key': base64.b64encode(public_key).decode('utf-8')
    })

@app.route('/api/users', methods=['GET'])
@rate_limit(max_calls=5, period=10)  # Max 5 calls per 10 seconds
def api_get_users():
    users = [{'username': user, 'online': True} for user in active_users.keys()]
    return jsonify({'users': users})

@app.route('/api/messages', methods=['GET'])
@rate_limit(max_calls=5, period=10)  # Max 5 calls per 10 seconds
def api_get_messages():
    username = request.args.get('username')
    current_user = request.args.get('current_user')
    
    if username:
        # Get messages between current_user and username
        filtered = [m for m in messages_store 
                   if (m['sender'] == current_user and m['recipient'] == username) or
                      (m['sender'] == username and m['recipient'] == current_user)]
        return jsonify({'messages': filtered})
    
    return jsonify({'messages': messages_store})

@app.route('/api/encryptions', methods=['GET'])
def api_get_encryptions():
    username = request.args.get('username')
    if username:
        filtered = [e for e in encryptions_log if e['sender'] == username or e['recipient'] == username]
        return jsonify({'encryptions': filtered})
    return jsonify({'encryptions': encryptions_log})

@app.route('/api/hashing_details', methods=['GET'])
def api_hashing_details():
    try:
        # Compute SHA-256 hashes of encryption components on the server
        from Crypto.Hash import SHA256 as _SHA256
        details = []
        for enc in encryptions_log:
            try:
                sess = enc.get('session_key_encrypted') or ''
                nonce = enc.get('nonce') or ''
                cipher = enc.get('ciphertext') or ''
                tag = enc.get('tag') or ''
                sig = enc.get('signature') or ''

                import base64 as _b64
                def _h(b64s: str):
                    try:
                        raw = _b64.b64decode(b64s)
                        return _SHA256.new(raw).hexdigest()
                    except Exception:
                        return None

                details.append({
                    'id': enc.get('id'),
                    'timestamp': enc.get('timestamp'),
                    'sender': enc.get('sender'),
                    'recipient': enc.get('recipient'),
                    'encryption_type': enc.get('encryption_type', 'RSA-AES-GCM'),
                    'sha256': {
                        'ciphertext': _h(cipher),
                        'session_key': _h(sess),
                        'nonce': _h(nonce),
                        'tag': _h(tag),
                        'signature': _h(sig),
                    }
                })
            except Exception:
                continue
        return jsonify({'hashing': details})
    except Exception as e:
        return jsonify({'error': f'hashing details failed: {str(e)}'}), 500

@app.route('/api/decrypt', methods=['POST'])
@rate_limit(max_calls=5, period=10)
def api_decrypt():
    try:
        data = request.get_json(silent=True) or {}
        enc_id = data.get('id')
        current_user = data.get('current_user')
        if not enc_id or not current_user:
            return jsonify({'error': 'id and current_user required'}), 400

        # Locate encryption record
        record = next((e for e in encryptions_log if e.get('id') == enc_id), None)
        if not record:
            # Attempt to find via messages_store
            msg = next((m for m in messages_store if m.get('id') == enc_id), None)
            if msg:
                record = {
                    'id': msg['id'],
                    'recipient': msg['recipient'],
                    'sender': msg['sender'],
                    'session_key_encrypted': msg['encrypted_content']['session_key'],
                    'nonce': msg['encrypted_content']['nonce'],
                    'ciphertext': msg['encrypted_content']['ciphertext'],
                    'tag': msg['encrypted_content']['tag']
                }
        if not record:
            return jsonify({'error': 'Encryption record not found'}), 404

        # Only recipient can decrypt (session key is encrypted for recipient)
        if record.get('recipient') != current_user:
            return jsonify({'error': 'Forbidden'}), 403

        # Load recipient private key
        private_key, _ = load_keys(current_user)
        if not private_key:
            return jsonify({'error': 'Private key not found for current user'}), 404

        # Decode components
        import base64 as _b64
        try:
            encrypted_session_key = _b64.b64decode(record['session_key_encrypted'])
            nonce = _b64.b64decode(record['nonce'])
            ciphertext = _b64.b64decode(record['ciphertext'])
            tag = _b64.b64decode(record['tag'])
        except Exception:
            return jsonify({'error': 'Invalid encrypted payload'}), 400

        # Decrypt
        plaintext = decrypt_message(encrypted_session_key, nonce, ciphertext, tag, private_key)
        if plaintext is None:
            return jsonify({'error': 'Decryption failed'}), 500

        # Return plaintext; frontend will trigger download without displaying
        return jsonify({'ok': True, 'text': plaintext})
    except Exception as e:
        return jsonify({'error': f'Decrypt failed: {str(e)}'}), 500

@app.route('/api/verify_signature', methods=['POST'])
@rate_limit(max_calls=8, period=10)
def api_verify_signature():
    try:
        data = request.get_json(silent=True) or {}
        enc_id = data.get('id')
        current_user = data.get('current_user')
        if not enc_id:
            return jsonify({'error': 'id required'}), 400

        # Find record (prefer encryptions_log)
        record = next((e for e in encryptions_log if e.get('id') == enc_id), None)
        message_text = None
        if not record:
            msg = next((m for m in messages_store if m.get('id') == enc_id), None)
            if msg:
                record = {
                    'id': msg['id'],
                    'sender': msg['sender'],
                    'recipient': msg['recipient'],
                    'signature': msg.get('signature'),
                }
                message_text = msg.get('message')
        else:
            # Try find the plaintext in messages_store for exact signing input without returning it
            msg = next((m for m in messages_store if m.get('id') == enc_id), None)
            if msg:
                message_text = msg.get('message')

        if not record or not record.get('signature'):
            return jsonify({'error': 'Signature not available'}), 404

        sender = record.get('sender')
        if not sender:
            return jsonify({'error': 'Sender unknown'}), 400

        # Get sender public key (from memory or disk)
        if sender in active_users and active_users[sender].get('public_key'):
            sender_pub = active_users[sender]['public_key']
        else:
            _, sender_pub = load_keys(sender)
        if not sender_pub:
            return jsonify({'error': 'Sender public key not found'}), 404

        import base64 as _b64
        try:
            signature_bytes = _b64.b64decode(record['signature'])
        except Exception:
            return jsonify({'error': 'Invalid signature payload'}), 400

        # If we don't have plaintext (e.g. server restarted), attempt server-side decrypt for recipient
        if not message_text:
            # Only attempt if we have encrypted parts and caller is the recipient
            try:
                if record.get('recipient') and current_user and record['recipient'] == current_user:
                    import base64 as _b64
                    priv, _ = load_keys(current_user)
                    if priv and all(k in record for k in ('session_key_encrypted','nonce','ciphertext','tag')):
                        enc_key = _b64.b64decode(record['session_key_encrypted'])
                        n = _b64.b64decode(record['nonce'])
                        ct = _b64.b64decode(record['ciphertext'])
                        tg = _b64.b64decode(record['tag'])
                        recovered = decrypt_message(enc_key, n, ct, tg, priv)
                        if recovered:
                            message_text = recovered
            except Exception:
                pass
        # Still missing plaintext
        if not message_text:
            return jsonify({'ok': False, 'verified': False, 'reason': 'Plaintext unavailable on server for verification'}), 200

        try:
            import time as time_module
            t0 = time_module.perf_counter()
            is_ok = verify_signature(message_text, signature_bytes, sender_pub)
            t1 = time_module.perf_counter()
            verify_ms = (t1 - t0) * 1000
            verify_perf_log.append({'timestamp': datetime.now().isoformat(), 'time_ms': round(verify_ms, 3)})
        except Exception as e:
            return jsonify({'ok': False, 'verified': False, 'reason': f'Verification error: {str(e)}'}), 200

        return jsonify({
            'ok': True,
            'verified': bool(is_ok),
            'algorithm': 'RSA + SHA-256',
            'sender': sender
        })
    except Exception as e:
        return jsonify({'error': f'Verify failed: {str(e)}'}), 500

@app.route('/api/transcribe', methods=['POST'])
@rate_limit(max_calls=5, period=10)
def api_transcribe():
    try:
        # Lazy import to avoid requiring optional deps at startup
        try:
            from ai import transcribe_wav_bytes
        except ImportError:
            return jsonify({'error': 'AI module not available. Install Vosk and related deps.'}), 503

        if 'audio' not in request.files and not request.data:
            return jsonify({'error': 'No audio provided'}), 400

        # Support multipart form-data with file field 'audio' or raw body
        wav_bytes = None
        if 'audio' in request.files:
            wav_bytes = request.files['audio'].read()
        else:
            wav_bytes = request.data

        if not wav_bytes:
            return jsonify({'error': 'Empty audio payload'}), 400

        text = transcribe_wav_bytes(wav_bytes)
        if text.startswith('Transcription error') or text.startswith('Voice-to-Text failed'):
            return jsonify({'error': text}), 500
        return jsonify({'text': text})
    except Exception as e:
        return jsonify({'error': f'Transcription failed: {str(e)}'}), 500

@app.route('/api/analytics', methods=['GET'])
def api_get_analytics():
    # Calculate analytics
    total_messages = len(messages_store)
    total_encryptions = len(encryptions_log)
    unique_users = set()
    for msg in messages_store:
        unique_users.add(msg['sender'])
        unique_users.add(msg['recipient'])
    
    # Messages by user
    messages_by_user = {}
    for msg in messages_store:
        messages_by_user[msg['sender']] = messages_by_user.get(msg['sender'], 0) + 1
    
    top_sender = max(messages_by_user.items(), key=lambda x: x[1])[0] if messages_by_user else None
    
    # Encryption timing statistics
    encryption_times = [enc.get('encryption_time_ms', 0) for enc in encryptions_log if 'encryption_time_ms' in enc]
    avg_encryption_time = sum(encryption_times) / len(encryption_times) if encryption_times else 0
    min_encryption_time = min(encryption_times) if encryption_times else 0
    max_encryption_time = max(encryption_times) if encryption_times else 0
    
    # Time series (per hour) for encryption, hashing, signing, verification
    encryption_time_series = []
    hashing_time_series = []
    signature_time_series = []
    verification_time_series = []

    if encryptions_log:
        # Group by hour for the last 24 hours
        enc_groups = defaultdict(list)
        hash_groups = defaultdict(list)
        sign_groups = defaultdict(list)
        for enc in encryptions_log:
            if 'timestamp' not in enc:
                continue
            try:
                enc_time = datetime.fromisoformat(enc['timestamp'])
                hour_key = enc_time.strftime('%Y-%m-%d %H:00')
                if 'encryption_time_ms' in enc:
                    enc_groups[hour_key].append(enc['encryption_time_ms'])
                if 'hash_time_ms' in enc:
                    hash_groups[hour_key].append(enc['hash_time_ms'])
                if 'signature_time_ms' in enc:
                    sign_groups[hour_key].append(enc['signature_time_ms'])
            except:
                pass

        for hour_key in sorted(enc_groups.keys())[-24:]:
            avg_time = sum(enc_groups[hour_key]) / len(enc_groups[hour_key])
            encryption_time_series.append({'time': hour_key, 'avg_time_ms': round(avg_time, 3), 'count': len(enc_groups[hour_key])})
        for hour_key in sorted(hash_groups.keys())[-24:]:
            avg_time = sum(hash_groups[hour_key]) / len(hash_groups[hour_key])
            hashing_time_series.append({'time': hour_key, 'avg_time_ms': round(avg_time, 3), 'count': len(hash_groups[hour_key])})
        for hour_key in sorted(sign_groups.keys())[-24:]:
            avg_time = sum(sign_groups[hour_key]) / len(sign_groups[hour_key])
            signature_time_series.append({'time': hour_key, 'avg_time_ms': round(avg_time, 3), 'count': len(sign_groups[hour_key])})

    if verify_perf_log:
        ver_groups = defaultdict(list)
        for v in verify_perf_log:
            try:
                t = datetime.fromisoformat(v.get('timestamp'))
                hour_key = t.strftime('%Y-%m-%d %H:00')
                ver_groups[hour_key].append(v.get('time_ms', 0))
            except:
                pass
        for hour_key in sorted(ver_groups.keys())[-24:]:
            avg_time = sum(ver_groups[hour_key]) / len(ver_groups[hour_key])
            verification_time_series.append({'time': hour_key, 'avg_time_ms': round(avg_time, 3), 'count': len(ver_groups[hour_key])})
    
    # Hashing timing statistics
    hashing_times = [enc.get('hash_time_ms', 0) for enc in encryptions_log if 'hash_time_ms' in enc]
    avg_hash_time = sum(hashing_times) / len(hashing_times) if hashing_times else 0
    min_hash_time = min(hashing_times) if hashing_times else 0
    max_hash_time = max(hashing_times) if hashing_times else 0

    # Signature timing statistics
    signature_times = [enc.get('signature_time_ms', 0) for enc in encryptions_log if 'signature_time_ms' in enc]
    avg_signature_time = sum(signature_times) / len(signature_times) if signature_times else 0
    min_signature_time = min(signature_times) if signature_times else 0
    max_signature_time = max(signature_times) if signature_times else 0

    # Signature verification timing statistics
    verify_times = [v.get('time_ms', 0) for v in verify_perf_log]
    avg_verify_time = sum(verify_times) / len(verify_times) if verify_times else 0
    min_verify_time = min(verify_times) if verify_times else 0
    max_verify_time = max(verify_times) if verify_times else 0

    # Message size statistics
    message_sizes = [enc.get('message_size_bytes', 0) for enc in encryptions_log if 'message_size_bytes' in enc]
    avg_message_size = sum(message_sizes) / len(message_sizes) if message_sizes else 0
    
    # Messages per hour
    messages_per_hour = defaultdict(int)
    for msg in messages_store:
        if 'timestamp' in msg:
            try:
                msg_time = datetime.fromisoformat(msg['timestamp'])
                hour_key = msg_time.strftime('%Y-%m-%d %H:00')
                messages_per_hour[hour_key] += 1
            except:
                pass
    
    # Messages per hour series (for graph)
    messages_per_hour_series = []
    for hour_key in sorted(messages_per_hour.keys())[-24:]:  # Last 24 hours
        messages_per_hour_series.append({
            'time': hour_key,
            'count': messages_per_hour[hour_key]
        })
    
    # Encryption types
    encryption_types = {}
    for enc in encryptions_log:
        enc_type = enc.get('encryption_type', 'Unknown')
        encryption_types[enc_type] = encryption_types.get(enc_type, 0) + 1
    
    # Performance metrics
    encryption_times_sorted = sorted(encryption_times) if encryption_times else []
    median_encryption_time = encryption_times_sorted[len(encryption_times_sorted) // 2] if encryption_times_sorted else 0
    hashing_times_sorted = sorted(hashing_times) if hashing_times else []
    median_hash_time = hashing_times_sorted[len(hashing_times_sorted) // 2] if hashing_times_sorted else 0
    signature_times_sorted = sorted(signature_times) if signature_times else []
    median_signature_time = signature_times_sorted[len(signature_times_sorted) // 2] if signature_times_sorted else 0
    verify_times_sorted = sorted(verify_times) if verify_times else []
    median_verify_time = verify_times_sorted[len(verify_times_sorted) // 2] if verify_times_sorted else 0
    
    return jsonify({
        'total_messages': total_messages,
        'total_encryptions': total_encryptions,
        'unique_users': len(unique_users),
        'top_sender': top_sender,
        'messages_by_user': messages_by_user,
        'encryption_types': encryption_types,
        'encryption_timing': {
            'avg_ms': round(avg_encryption_time, 3),
            'min_ms': round(min_encryption_time, 3),
            'max_ms': round(max_encryption_time, 3),
            'median_ms': round(median_encryption_time, 3),
            'total_samples': len(encryption_times)
        },
        'hashing_timing': {
            'avg_ms': round(avg_hash_time, 3),
            'min_ms': round(min_hash_time, 3),
            'max_ms': round(max_hash_time, 3),
            'median_ms': round(median_hash_time, 3),
            'total_samples': len(hashing_times)
        },
        'signature_timing': {
            'avg_ms': round(avg_signature_time, 3),
            'min_ms': round(min_signature_time, 3),
            'max_ms': round(max_signature_time, 3),
            'median_ms': round(median_signature_time, 3),
            'total_samples': len(signature_times)
        },
        'signature_verification_timing': {
            'avg_ms': round(avg_verify_time, 3),
            'min_ms': round(min_verify_time, 3),
            'max_ms': round(max_verify_time, 3),
            'median_ms': round(median_verify_time, 3),
            'total_samples': len(verify_times)
        },
        'encryption_time_series': encryption_time_series,
        'hashing_time_series': hashing_time_series,
        'signature_time_series': signature_time_series,
        'verification_time_series': verification_time_series,
        'verification_samples': verify_perf_log,
        'message_stats': {
            'avg_size_bytes': round(avg_message_size, 2),
            'total_size_bytes': sum(message_sizes)
        }
    })

@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    print(f'Client disconnected: {request.sid}')
    # Remove user from active users
    username = None
    if hasattr(socketio, 'user_sessions'):
        username = socketio.user_sessions.get(request.sid)
        # Safely remove without KeyError if missing
        try:
            socketio.user_sessions.pop(request.sid, None)
        except Exception:
            pass
    
    if not username:
        for user, data in list(active_users.items()):
            if data.get('socket_id') == request.sid:
                username = user
                break
    
    if username and username in active_users:
        del active_users[username]
        socketio.emit('user_left', {'username': username}, broadcast=True)

@socketio.on('register')
def handle_register(data):
    username = data.get('username')
    public_key_b64 = data.get('public_key')
    
    if username:
        # Load or get public key
        if public_key_b64:
            public_key = base64.b64decode(public_key_b64)
        else:
            _, public_key = load_keys(username)
            if not public_key:
                _, public_key = generate_key_pair()
                save_keys(_, public_key, username)
        
        active_users[username] = {
            'socket_id': request.sid,
            'public_key': public_key,
            'joined_at': datetime.now().isoformat()
        }
        # Store username in session-like way (using a dict since session doesn't work well with socketio)
        if not hasattr(socketio, 'user_sessions'):
            socketio.user_sessions = {}
        socketio.user_sessions[request.sid] = username
        emit('registration_success', {'username': username, 'public_key': base64.b64encode(public_key).decode('utf-8')})
        # Broadcast using context-bound emit to avoid Server.emit() kwargs mismatch
        emit('user_joined', {'username': username}, broadcast=True, include_self=False)
        print(f'User {username} registered (Socket ID: {request.sid})')

@socketio.on('get_public_key')
def handle_get_public_key(data):
    recipient = data.get('recipient')
    username = socketio.user_sessions.get(request.sid) if hasattr(socketio, 'user_sessions') else None
    
    if recipient in active_users:
        public_key = active_users[recipient]['public_key']
        emit('public_key_response', {
            'recipient': recipient,
            'public_key': base64.b64encode(public_key).decode('utf-8'),
            'status': 'success'
        })
    else:
        emit('public_key_response', {
            'recipient': recipient,
            'status': 'error',
            'message': 'User not found'
        })

@socketio.on('send_message')
def handle_send_message(data):
    sender = socketio.user_sessions.get(request.sid) if hasattr(socketio, 'user_sessions') else None
    if not sender:
        emit('error', {'message': 'Not authenticated'})
        return
    
    recipient = data.get('recipient')
    message_text = data.get('message')
    
    if not recipient or not message_text:
        emit('error', {'message': 'Recipient and message required'})
        return
    
    # Get recipient's public key
    if recipient not in active_users:
        emit('error', {'message': 'Recipient not online'})
        return
    
    recipient_public_key = active_users[recipient]['public_key']
    sender_private_key, _ = load_keys(sender)
    
    if not sender_private_key:
        emit('error', {'message': 'Sender keys not found'})
        return
    
    try:
        # Track encryption/signing/hashing times
        import time as time_module
        encryption_start = time_module.perf_counter()

        # Sign timing
        sign_start = time_module.perf_counter()
        signature = sign_message(message_text, sender_private_key)
        sign_end = time_module.perf_counter()
        signature_time_ms = (sign_end - sign_start) * 1000

        # Hash timing (SHA-256 of plaintext)
        hash_start = time_module.perf_counter()
        from Crypto.Hash import SHA256 as _SHA256
        _ = _SHA256.new(message_text.encode('utf-8')).digest()
        hash_end = time_module.perf_counter()
        hash_time_ms = (hash_end - hash_start) * 1000

        # Encrypt
        encrypted_session_key, nonce, ciphertext, tag = encrypt_message(message_text, recipient_public_key)

        # Calculate encryption time
        encryption_end = time_module.perf_counter()
        encryption_time_ms = (encryption_end - encryption_start) * 1000  # Convert to milliseconds
        
        # Track message size
        message_size = len(message_text.encode('utf-8'))
        
        # Log encryption with timing data
        encryption_record = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'sender': sender,
            'recipient': recipient,
            'encryption_type': 'RSA-AES-GCM',
            'encryption_time_ms': round(encryption_time_ms, 3),
            'message_size_bytes': message_size,
            'signature_time_ms': round(signature_time_ms, 3),
            'hash_time_ms': round(hash_time_ms, 3),
            'session_key_encrypted': base64.b64encode(encrypted_session_key).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'signature': base64.b64encode(signature).decode('utf-8')
        }
        encryptions_log.append(encryption_record)
        
        # Create message object
        message_obj = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'sender': sender,
            'recipient': recipient,
            'message': message_text,
            'encrypted_content': {
                'session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
                'nonce': base64.b64encode(nonce).decode('utf-8'),
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8')
            },
            'signature': base64.b64encode(signature).decode('utf-8')
        }
        
        messages_store.append(message_obj)
        
        # Send to recipient if online
        recipient_socket_id = active_users[recipient]['socket_id']
        socketio.emit('new_message', {
            'sender': sender,
            'message': message_text,
            'encrypted_content': message_obj['encrypted_content'],
            'signature': message_obj['signature'],
            'timestamp': message_obj['timestamp'],
            'id': message_obj['id']
        }, room=recipient_socket_id)
        
        # Confirm to sender
        emit('message_sent', {
            'recipient': recipient,
            'message': message_text,
            'timestamp': message_obj['timestamp'],
            'id': message_obj['id']
        })
        
        # Removed message_update broadcast - it was causing spam API calls
        
    except Exception as e:
        emit('error', {'message': f'Failed to send message: {str(e)}'})
        print(f"Error sending message: {e}")

@socketio.on('voice_message')
def handle_voice_message(data):
    sender = socketio.user_sessions.get(request.sid) if hasattr(socketio, 'user_sessions') else None
    if not sender:
        emit('error', {'message': 'Not authenticated'})
        return
    
    recipient = data.get('recipient')
    
    # Use voice_to_text function
    if not AI_AVAILABLE:
        emit('error', {'message': 'Voice-to-text feature is not available. Please install required dependencies.'})
        return
    
    try:
        text_input = voice_to_text()
        if text_input:
            # Send the converted text as a message
            handle_send_message({
                'recipient': recipient,
                'message': text_input
            })
            emit('voice_converted', {'text': text_input})
        else:
            emit('error', {'message': 'Voice conversion failed'})
    except Exception as e:
        emit('error', {'message': f'Voice conversion error: {str(e)}'})

if __name__ == '__main__':
    print("=" * 50)
    print("Starting CipherTalk Web Server...")
    print("=" * 50)
    print("\n📱 Open http://localhost:5000 in your browser")
    print("🔐 Secure messaging with end-to-end encryption")
    print("🎤 Voice-to-text support included")
    print("=" * 50 + "\n")
    socketio.run(app, debug=True, port=5000, host='0.0.0.0')


# CipherTalk - Secure Messaging App

A modern, secure messaging application with end-to-end encryption, voice-to-text, and analytics.

## Features

- 🔐 **End-to-End Encryption**: RSA-AES hybrid encryption for secure messaging
- 💬 **Real-time Messaging**: WebSocket-based real-time chat
- 🎤 **Voice-to-Text**: Convert voice messages to text using Vosk
- 📊 **Analytics Dashboard**: View message and encryption statistics
- 🔒 **Encryption History**: View all encryption operations
- 🎨 **Modern UI**: Clean, responsive web interface

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

**Note**: You may need to install additional dependencies:
- For voice-to-text: Install Vosk model in a `model` folder (download from https://alphacephei.com/vosk/models)
- For NLP: Run `python -m spacy download en_core_web_sm`

### 2. Run the Web Server

```bash
python web_server.py
```

### 3. Open in Browser

Navigate to: **http://localhost:5000**

## Usage

1. **Login**: Enter a username to start chatting
2. **Select User**: Click on a user from the sidebar to start a conversation
3. **Send Messages**: Type and send encrypted messages
4. **Voice Messages**: Click the microphone button to use voice-to-text
5. **View Encryptions**: Click "🔒 View Encryptions" to see all encryption operations
6. **Analytics**: Click "📊 Analytics" to view statistics

## Project Structure

```
codes/
├── web_server.py      # Flask web server with SocketIO
├── clientv1.py        # Original CLI client (legacy)
├── server.py          # Original socket server (legacy)
├── crypto.py          # Encryption/decryption functions
├── ai.py              # Voice-to-text and summarization
├── templates/
│   └── index.html     # Main UI template
├── static/
│   ├── style.css      # Styles
│   └── app.js         # Frontend JavaScript
└── requirements.txt   # Python dependencies
```

## Next Steps

- [ ] Add database persistence (SQLite/PostgreSQL)
- [ ] Enhanced analytics with charts
- [ ] Message history persistence
- [ ] User authentication
- [ ] Message search functionality

## Development

The web UI uses:
- **Backend**: Flask + Flask-SocketIO
- **Frontend**: Vanilla JavaScript + Socket.IO client
- **Styling**: Modern CSS with gradient design


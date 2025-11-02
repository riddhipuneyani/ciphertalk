# Quick Start Guide - Testing CipherTalk

## Step 1: Start the Server

Run this command in your terminal:
```bash
python web_server.py
```

OR double-click `start_server.bat` on Windows.

## Step 2: Open in Browser

Open your web browser and navigate to:
```
http://localhost:5000
```

## Step 3: Test Basic Features

### Login
1. Enter a username (e.g., "Alice")
2. Click "Login"
3. You should see the conversations sidebar appear

### Test Messaging (Need 2+ Users)
1. **Window 1**: Login as "Alice"
2. **Window 2**: Open a new tab/window, go to `http://localhost:5000`, login as "Bob"
3. **In Alice's window**: Click on "Bob" in the user list
4. **Send a message**: Type "Hello!" and click Send
5. **Check Bob's window**: The message should appear automatically

### View Encryptions
1. After sending some messages, click "🔒 View Encryptions" button
2. You should see all encryption operations listed with details

### View Analytics
1. Click "📊 Analytics" button
2. View statistics about messages, encryptions, and users

## Troubleshooting

- **Port 5000 already in use?** Change the port in `web_server.py` line 315
- **Dependencies missing?** Run `pip install -r requirements.txt`
- **Server not starting?** Check for error messages in the terminal

## Testing Checklist

- [ ] Server starts without errors
- [ ] Can login with username
- [ ] Can see other logged-in users
- [ ] Can send messages between users
- [ ] Messages appear in real-time
- [ ] Encryption history works
- [ ] Analytics dashboard works


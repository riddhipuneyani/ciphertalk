// Initialize Socket.IO connection
let socket;
let currentUsername = '';
let currentRecipient = null;
let messages = [];
let isLoadingUsers = false;
let isLoadingMessages = false;
let debounceTimer = null;
let lastLoadUsersTime = 0;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initializeSocket();
    setupEventListeners();
});

function initializeSocket() {
    socket = io();
    
    socket.on('connect', () => {
        console.log('Connected to server');
    });
    
    socket.on('disconnect', () => {
        console.log('Disconnected from server');
    });
    
    socket.on('registration_success', (data) => {
        currentUsername = data.username;
        document.getElementById('current-user').textContent = `Logged in as: ${data.username}`;
        document.getElementById('login-section').style.display = 'none';
        document.getElementById('conversations-section').style.display = 'block';
        document.getElementById('logout-btn').style.display = 'block';
        // Only load users once after successful registration with delay
        if (currentUsername) {
            setTimeout(() => {
                if (currentUsername) {
                    loadUsers();
                }
            }, 300);
        }
    });
    
    // DISABLED - was causing spam API calls
    // Users list will update when needed (on login, manual refresh)
    socket.on('user_joined', (data) => {
        console.log('User joined:', data.username);
        // Don't auto-refresh - user can refresh manually if needed
    });
    
    socket.on('user_left', (data) => {
        console.log('User left:', data.username);
        // Don't auto-refresh - user can refresh manually if needed
    });
    
    socket.on('new_message', (data) => {
        addMessage(data.sender, data.message, false, data.timestamp, data.id);
    });
    
    socket.on('message_sent', (data) => {
        addMessage(currentUsername, data.message, true, data.timestamp, data.id);
        document.getElementById('message-input').value = '';
    });
    
    // Removed message_update handler - messages come via new_message and message_sent events
    // This was causing spam API calls
    
    socket.on('error', (data) => {
        alert('Error: ' + data.message);
    });
    
    socket.on('voice_converted', (data) => {
        console.log('Voice converted:', data.text);
    });
}

function setupEventListeners() {
    // Login
    document.getElementById('login-btn').addEventListener('click', handleLogin);
    document.getElementById('username-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleLogin();
    });
    
    // Logout
    document.getElementById('logout-btn').addEventListener('click', handleLogout);
    
    // Send message
    document.getElementById('send-btn').addEventListener('click', sendMessage);
    document.getElementById('message-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });
    
    // Voice button
    document.getElementById('voice-btn').addEventListener('click', handleVoiceMessage);
    
    // Summarize button
    document.getElementById('summarize-btn').addEventListener('click', handleSummarize);
    
    // View encryptions
    document.getElementById('view-encryptions-btn').addEventListener('click', () => {
        document.getElementById('encryptions-modal').style.display = 'flex';
        loadEncryptions();
    });
    
    // View analytics
    document.getElementById('view-analytics-btn').addEventListener('click', () => {
        document.getElementById('analytics-modal').style.display = 'flex';
        loadAnalytics();
    });
    
    // View hashing
    document.getElementById('view-hashing-btn').addEventListener('click', () => {
        document.getElementById('hashing-modal').style.display = 'flex';
        loadHashing();
    });

    // View digital signature verification
    document.getElementById('view-signature-btn').addEventListener('click', () => {
        document.getElementById('signature-modal').style.display = 'flex';
        loadSignatureVerification();
    });
    
    // Close modals
    document.querySelectorAll('.close').forEach(closeBtn => {
        closeBtn.addEventListener('click', (e) => {
            e.target.closest('.modal').style.display = 'none';
        });
    });
    
    // Close modal on outside click
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.style.display = 'none';
            }
        });
    });
}
// ---- Digital Signature Verification ----
async function loadSignatureVerification() {
    const container = document.getElementById('signature-content');
    container.innerHTML = '<p>Verifying signatures...</p>';
    try {
        const response = await fetch('/api/encryptions');
        const data = await response.json();
        if (!data.encryptions || data.encryptions.length === 0) {
            container.innerHTML = '<p>No encryption records found</p>';
            return;
        }

        const rows = [];
        for (const enc of data.encryptions) {
            let result = { ok: false, verified: false, reason: 'N/A' };
            try {
                const res = await fetch('/api/verify_signature', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id: enc.id, current_user: currentUsername })
                });
                result = await res.json();
            } catch (e) {
                result = { ok: false, verified: false, reason: 'Network error' };
            }

            const time = new Date(enc.timestamp).toLocaleString();
            const statusText = result.verified ? '✅ Verified' : '❌ Not Verified';
            const reasonText = result.reason ? ` — ${escapeHtml(result.reason)}` : '';
            rows.push(`
                <div class="encryption-item">
                    <div class="encryption-item-header">
                        <div class="encryption-item-title">${enc.encryption_type || 'Encrypted Message'}</div>
                        <div class="encryption-item-time">${time}</div>
                    </div>
                    <div class="encryption-item-details">
                        <div><strong>From:</strong> ${enc.sender}</div>
                        <div><strong>To:</strong> ${enc.recipient}</div>
                        <div><strong>Signature Status:</strong> ${statusText}${reasonText}</div>
                        ${result.algorithm ? `<div><strong>Algorithm:</strong> ${result.algorithm}</div>` : ''}
                    </div>
                </div>
            `);
        }
        container.innerHTML = rows.join('');
    } catch (err) {
        console.error('Error loading signature verification:', err);
        container.innerHTML = '<p>Failed to load signature verification details.</p>';
    }
}
// ---- Hashing (SHA-256) ----
async function loadHashing() {
    const container = document.getElementById('hashing-content');
    container.innerHTML = '<p>Loading hashing details...</p>';
    try {
        const response = await fetch('/api/encryptions');
        const data = await response.json();
        if (!data.encryptions || data.encryptions.length === 0) {
            container.innerHTML = '<p>No encryption records found</p>';
            return;
        }

        const itemsHtml = await Promise.all(data.encryptions.map(async (enc) => {
            const toHex = (buf) => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
            const b64ToBytes = (b64) => {
                const str = atob(b64 || '');
                const arr = new Uint8Array(str.length);
                for (let i = 0; i < str.length; i++) arr[i] = str.charCodeAt(i);
                return arr;
            };
            const sha256 = async (bytes) => {
                const digest = await crypto.subtle.digest('SHA-256', bytes);
                return toHex(digest);
            };

            const ts = new Date(enc.timestamp).toLocaleString();
            const ciphHash = enc.ciphertext ? await sha256(b64ToBytes(enc.ciphertext)) : 'N/A';
            const sessHash = enc.session_key_encrypted ? await sha256(b64ToBytes(enc.session_key_encrypted)) : 'N/A';
            const nonceHash = enc.nonce ? await sha256(b64ToBytes(enc.nonce)) : 'N/A';
            const tagHash = enc.tag ? await sha256(b64ToBytes(enc.tag)) : 'N/A';
            const sigHash = enc.signature ? await sha256(b64ToBytes(enc.signature)) : 'N/A';

            return `
                <div class="encryption-item">
                    <div class="encryption-item-header">
                        <div class="encryption-item-title">${enc.encryption_type || 'Encrypted Message'}</div>
                        <div class="encryption-item-time">${ts}</div>
                    </div>
                    <div class="encryption-item-details">
                        <div><strong>From:</strong> ${enc.sender}</div>
                        <div><strong>To:</strong> ${enc.recipient}</div>
                        <div><strong>SHA-256 (Ciphertext):</strong> <code>${ciphHash}</code></div>
                        <div><strong>SHA-256 (Session Key):</strong> <code>${sessHash}</code></div>
                        <div><strong>SHA-256 (Nonce):</strong> <code>${nonceHash}</code></div>
                        <div><strong>SHA-256 (Tag):</strong> <code>${tagHash}</code></div>
                        <div><strong>SHA-256 (Signature):</strong> <code>${sigHash}</code></div>
                    </div>
                </div>
            `;
        }));

        container.innerHTML = itemsHtml.join('');
    } catch (err) {
        console.error('Error loading hashing details:', err);
        container.innerHTML = '<p>Failed to load hashing details.</p>';
    }
}

async function handleLogin() {
    const username = document.getElementById('username-input').value.trim();
    if (!username) {
        alert('Please enter a username');
        return;
    }
    
    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username })
        });
        
        const data = await response.json();
        if (data.success) {
            // Register with socket - loadUsers will be called by registration_success event
            socket.emit('register', {
                username: data.username,
                public_key: data.public_key
            });
        } else {
            alert('Login failed: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Login error:', error);
        alert('Login failed. Please try again.');
    }
}

function handleLogout() {
    currentUsername = '';
    currentRecipient = null;
    messages = [];
    document.getElementById('current-user').textContent = 'Not logged in';
    document.getElementById('login-section').style.display = 'block';
    document.getElementById('conversations-section').style.display = 'none';
    document.getElementById('logout-btn').style.display = 'none';
    document.getElementById('chat-header').style.display = 'none';
    document.getElementById('chat-input-section').style.display = 'none';
    document.getElementById('chat-messages').innerHTML = `
        <div class="welcome-message">
            <h3>Welcome to CipherTalk</h3>
            <p>Login and select a user to start a secure conversation</p>
        </div>
    `;
    socket.disconnect();
    initializeSocket();
}

async function loadUsers() {
    // STRICT rate limiting - prevent any spam
    const now = Date.now();
    if (isLoadingUsers || !currentUsername) {
        return;
    }
    
    // Enforce minimum 2 seconds between calls
    if (now - lastLoadUsersTime < 2000) {
        console.log('Rate limit: skipping loadUsers() call');
        return;
    }
    
    lastLoadUsersTime = now;
    isLoadingUsers = true;
    
    try {
        console.log('Loading users...');
        const response = await fetch('/api/users', {
            cache: 'no-store',
            headers: {
                'Cache-Control': 'no-cache'
            }
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        const usersList = document.getElementById('users-list');
        if (!usersList) {
            isLoadingUsers = false;
            return;
        }
        usersList.innerHTML = '';
        
        if (data.users && Array.isArray(data.users)) {
            data.users.forEach(user => {
                if (user.username === currentUsername) return;
                
                const userItem = document.createElement('div');
                userItem.className = 'user-item';
                userItem.innerHTML = `
                    <div class="user-item-name">${user.username}</div>
                    <div class="user-item-status">${user.online ? '🟢 Online' : '🔴 Offline'}</div>
                `;
                userItem.addEventListener('click', () => {
                    selectUser(user.username);
                });
                usersList.appendChild(userItem);
            });
        }
        console.log('Users loaded successfully');
    } catch (error) {
        console.error('Error loading users:', error);
    } finally {
        isLoadingUsers = false;
    }
}

function selectUser(username) {
    currentRecipient = username;
    
    // Update UI - mark active user
    document.querySelectorAll('.user-item').forEach(item => {
        if (item.querySelector('.user-item-name').textContent === username) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });
    
    document.getElementById('chat-recipient').textContent = `Chatting with ${username}`;
    document.getElementById('chat-header').style.display = 'flex';
    document.getElementById('chat-input-section').style.display = 'block';
    
    loadMessages(username);
}

let lastLoadMessagesTime = 0;
let lastLoadMessagesUser = '';

async function loadMessages(username) {
    // STRICT rate limiting
    const now = Date.now();
    if (isLoadingMessages || !username || !currentUsername) {
        return;
    }
    
    // Enforce minimum 1 second between calls for same user, 2 seconds for different user
    const minDelay = (username === lastLoadMessagesUser) ? 1000 : 2000;
    if (now - lastLoadMessagesTime < minDelay) {
        console.log('Rate limit: skipping loadMessages() call');
        return;
    }
    
    lastLoadMessagesTime = now;
    lastLoadMessagesUser = username;
    isLoadingMessages = true;
    
    try {
        console.log(`Loading messages for ${username}...`);
        const response = await fetch(`/api/messages?username=${username}&current_user=${currentUsername}`, {
            cache: 'no-store',
            headers: {
                'Cache-Control': 'no-cache'
            }
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        messages = data.messages || [];
        displayMessages();
        console.log('Messages loaded successfully');
    } catch (error) {
        console.error('Error loading messages:', error);
    } finally {
        isLoadingMessages = false;
    }
}

function displayMessages() {
    const messagesContainer = document.getElementById('chat-messages');
    messagesContainer.innerHTML = '';
    
    if (messages.length === 0) {
        messagesContainer.innerHTML = `
            <div class="welcome-message">
                <h3>No messages yet</h3>
                <p>Start the conversation!</p>
            </div>
        `;
        return;
    }
    
    messages.forEach(msg => {
        const isSent = msg.sender === currentUsername;
        addMessage(msg.sender, msg.message, isSent, msg.timestamp, msg.id, false);
    });
    
    // Scroll to bottom
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function addMessage(sender, message, isSent, timestamp, id, append = true) {
    const messagesContainer = document.getElementById('chat-messages');
    
    // Remove welcome message if exists
    const welcomeMsg = messagesContainer.querySelector('.welcome-message');
    if (welcomeMsg) {
        welcomeMsg.remove();
    }
    
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
    messageDiv.id = `msg-${id}`;
    
    const time = timestamp ? new Date(timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
    
    messageDiv.innerHTML = `
        <div class="message-header">${isSent ? 'You' : sender}</div>
        <div class="message-content">${escapeHtml(message)}</div>
        <div class="message-time">${time}</div>
    `;
    
    if (append) {
        messagesContainer.appendChild(messageDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    } else {
        messagesContainer.insertBefore(messageDiv, messagesContainer.firstChild);
    }
}

function sendMessage() {
    const messageInput = document.getElementById('message-input');
    const message = messageInput.value.trim();
    
    if (!message || !currentRecipient) {
        return;
    }
    
    socket.emit('send_message', {
        recipient: currentRecipient,
        message: message
    });
}

function handleVoiceMessage() {
    if (!currentRecipient) {
        alert('Please select a recipient first');
        return;
    }
    // Use browser STT only (simplest, no server deps)
    const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SpeechRec) {
        alert('Speech recognition not supported in this browser. Please use Chrome or Edge on desktop and allow microphone access.');
        return;
    }
    startBrowserSpeechRecognition((text) => {
        if (text && text.trim()) {
            socket.emit('send_message', { recipient: currentRecipient, message: text.trim() });
        } else {
            alert('No speech detected.');
        }
    });
}

async function handleSummarize() {
    if (messages.length === 0) {
        alert('No messages to summarize');
        return;
    }
    
    // Get last received message
    const lastReceived = messages.filter(m => m.sender !== currentUsername).pop();
    if (!lastReceived) {
        alert('No received messages to summarize');
        return;
    }
    
    // In a real implementation, this would call the backend AI service
    alert('Summarization feature - would summarize: ' + lastReceived.message.substring(0, 50) + '...');
}

async function loadEncryptions() {
    try {
        const response = await fetch('/api/encryptions');
        const data = await response.json();
        const encryptionsList = document.getElementById('encryptions-list');
        encryptionsList.innerHTML = '';
        
        if (data.encryptions.length === 0) {
            encryptionsList.innerHTML = '<p>No encryption records found</p>';
            return;
        }
        
        data.encryptions.forEach(enc => {
            const encItem = document.createElement('div');
            encItem.className = 'encryption-item';
            const time = new Date(enc.timestamp).toLocaleString();
            const cipherPreview = (enc.ciphertext || '').substring(0, 48) + '...';
            const sessPreview = (enc.session_key_encrypted || '').substring(0, 30) + '...';
            const noncePreview = (enc.nonce || '').substring(0, 20) + '...';
            const tagPreview = (enc.tag || '').substring(0, 20) + '...';
            const sigPreview = (enc.signature || '').substring(0, 30) + '...';
            encItem.innerHTML = `
                <div class="encryption-item-header">
                    <div class="encryption-item-title">${enc.encryption_type || 'Encrypted Message'}</div>
                    <div class="encryption-item-time">${time}</div>
                </div>
                <div class="encryption-item-details">
                    <div><strong>From:</strong> ${enc.sender}</div>
                    <div><strong>To:</strong> ${enc.recipient}</div>
                    <div><strong>Ciphertext:</strong> <code title="Encrypted text">${cipherPreview}</code></div>
                    <div><strong>Session Key:</strong> <code>${sessPreview}</code></div>
                    <div><strong>Nonce:</strong> <code>${noncePreview}</code></div>
                    <div><strong>Tag:</strong> <code>${tagPreview}</code></div>
                    ${enc.signature ? `<div><strong>Signature:</strong> <code>${sigPreview}</code></div>` : ''}
                    <div style="margin-top:10px; display:flex; gap:8px;">
                        <button class="btn-secondary" data-decrypt-id="${enc.id}">Decrypt (download)</button>
                    </div>
                </div>
            `;
            encryptionsList.appendChild(encItem);
        });

        // Attach decrypt handlers
        encryptionsList.querySelectorAll('[data-decrypt-id]').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const id = e.currentTarget.getAttribute('data-decrypt-id');
                if (!id || !currentUsername) return;
                try {
                    const res = await fetch('/api/decrypt', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ id, current_user: currentUsername })
                    });
                    const payload = await res.json();
                    if (!res.ok || !payload.ok) {
                        alert('Decrypt failed: ' + (payload.error || res.statusText));
                        return;
                    }
                    // Create a temporary download without showing the text on screen
                    const blob = new Blob([payload.text], { type: 'text/plain;charset=utf-8' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `decrypted-${id.substring(0,8)}.txt`;
                    document.body.appendChild(a);
                    a.click();
                    setTimeout(() => {
                        document.body.removeChild(a);
                        URL.revokeObjectURL(url);
                    }, 0);
                } catch (err) {
                    console.error('Decrypt error', err);
                    alert('Decrypt failed.');
                }
            });
        });
    } catch (error) {
        console.error('Error loading encryptions:', error);
    }
}

let encryptionTimeChart = null;
let messagesPerHourChart = null;

async function loadAnalytics() {
    try {
        const response = await fetch('/api/analytics');
        const data = await response.json();
        
        const analyticsContent = document.getElementById('analytics-content');
        
        // Overall statistics
        const timing = data.encryption_timing || {};
        const messageStats = data.message_stats || {};
        
        analyticsContent.innerHTML = `
            <div class="analytics-grid">
                <div class="analytics-card">
                    <h3>📊 Overall Statistics</h3>
                    <div class="analytics-stat">
                        <span class="stat-label">Total Messages</span>
                        <span class="stat-value">${data.total_messages || 0}</span>
                    </div>
                    <div class="analytics-stat">
                        <span class="stat-label">Total Encryptions</span>
                        <span class="stat-value">${data.total_encryptions || 0}</span>
                    </div>
                    <div class="analytics-stat">
                        <span class="stat-label">Active Users</span>
                        <span class="stat-value">${data.unique_users || 0}</span>
                    </div>
                    <div class="analytics-stat">
                        <span class="stat-label">Top Sender</span>
                        <span class="stat-value">${data.top_sender || 'N/A'}</span>
                    </div>
                </div>
                
                <div class="analytics-card">
                    <h3>⚡ Encryption Performance</h3>
                    <div class="analytics-stat">
                        <span class="stat-label">Avg Encryption Time</span>
                        <span class="stat-value">${timing.avg_ms || 0} ms</span>
                    </div>
                    <div class="analytics-stat">
                        <span class="stat-label">Min Time</span>
                        <span class="stat-value">${timing.min_ms || 0} ms</span>
                    </div>
                    <div class="analytics-stat">
                        <span class="stat-label">Max Time</span>
                        <span class="stat-value">${timing.max_ms || 0} ms</span>
                    </div>
                    <div class="analytics-stat">
                        <span class="stat-label">Median Time</span>
                        <span class="stat-value">${timing.median_ms || 0} ms</span>
                    </div>
                    <div class="analytics-stat">
                        <span class="stat-label">Total Samples</span>
                        <span class="stat-value">${timing.total_samples || 0}</span>
                    </div>
                </div>
                
                <div class="analytics-card">
                    <h3>💬 Message Statistics</h3>
                    <div class="analytics-stat">
                        <span class="stat-label">Avg Message Size</span>
                        <span class="stat-value">${Math.round(messageStats.avg_size_bytes || 0)} bytes</span>
                    </div>
                    <div class="analytics-stat">
                        <span class="stat-label">Total Size</span>
                        <span class="stat-value">${formatBytes(messageStats.total_size_bytes || 0)}</span>
                    </div>
                </div>
            </div>
            
            <div class="chart-container">
                <h3>📈 Encryption Time Over Time</h3>
                <canvas id="encryptionTimeChart"></canvas>
            </div>
            
            <div class="chart-container">
                <h3>📊 Messages Per Hour</h3>
                <canvas id="messagesPerHourChart"></canvas>
            </div>
        `;
        
        // Create encryption time chart
        if (data.encryption_time_series && data.encryption_time_series.length > 0) {
            const ctx1 = document.getElementById('encryptionTimeChart').getContext('2d');
            
            // Destroy existing chart if it exists
            if (encryptionTimeChart) {
                encryptionTimeChart.destroy();
            }
            
            const labels = data.encryption_time_series.map(item => {
                // Format time for display
                const date = new Date(item.time);
                return date.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit' });
            });
            const times = data.encryption_time_series.map(item => item.avg_time_ms);
            const counts = data.encryption_time_series.map(item => item.count);
            
            encryptionTimeChart = new Chart(ctx1, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Avg Encryption Time (ms)',
                        data: times,
                        borderColor: 'rgb(52, 152, 219)',
                        backgroundColor: 'rgba(52, 152, 219, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            display: true
                        },
                        tooltip: {
                            callbacks: {
                                afterLabel: function(context) {
                                    const index = context.dataIndex;
                                    return `Count: ${counts[index]} encryptions`;
                                }
                            }
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Time (milliseconds)'
                            }
                        },
                        x: {
                            title: {
                                display: true,
                                text: 'Time'
                            }
                        }
                    }
                }
            });
        } else {
            document.getElementById('encryptionTimeChart').parentElement.innerHTML = 
                '<p style="text-align: center; color: #7f8c8d; padding: 20px;">No encryption data available yet. Send some messages to see performance metrics!</p>';
        }
        
        // Create messages per hour chart
        if (data.messages_per_hour && data.messages_per_hour.length > 0) {
            const ctx2 = document.getElementById('messagesPerHourChart').getContext('2d');
            
            // Destroy existing chart if it exists
            if (messagesPerHourChart) {
                messagesPerHourChart.destroy();
            }
            
            const labels = data.messages_per_hour.map(item => {
                const date = new Date(item.time);
                return date.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit' });
            });
            const counts = data.messages_per_hour.map(item => item.count);
            
            messagesPerHourChart = new Chart(ctx2, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Messages Sent',
                        data: counts,
                        backgroundColor: 'rgba(46, 204, 113, 0.7)',
                        borderColor: 'rgb(46, 204, 113)',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            display: true
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Number of Messages'
                            },
                            ticks: {
                                stepSize: 1
                            }
                        },
                        x: {
                            title: {
                                display: true,
                                text: 'Time'
                            }
                        }
                    }
                }
            });
        } else {
            document.getElementById('messagesPerHourChart').parentElement.innerHTML = 
                '<p style="text-align: center; color: #7f8c8d; padding: 20px;">No message activity data available yet.</p>';
        }
        
    } catch (error) {
        console.error('Error loading analytics:', error);
        const analyticsContent = document.getElementById('analytics-content');
        if (analyticsContent) {
            analyticsContent.innerHTML = `
                <div class="analytics-card" style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);">
                    <h3>❌ Error Loading Analytics</h3>
                    <p style="margin-top: 10px;">${error.message || 'Failed to load analytics data. Please refresh the page or check the server logs.'}</p>
                </div>
            `;
        }
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// ---- Browser Speech Recognition (Web Speech API) ----
function startBrowserSpeechRecognition(onResult) {
    const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SpeechRec) {
        alert('Speech recognition not supported in this browser.');
        return;
    }
    const btn = document.getElementById('voice-btn');
    const prev = btn.textContent;
    btn.textContent = '⏹';
    btn.classList.add('recording');

    const rec = new SpeechRec();
    rec.lang = 'en-US';
    rec.interimResults = false;
    rec.maxAlternatives = 1;

    let stopped = false;
    const stop = () => {
        if (stopped) return;
        stopped = true;
        try { rec.stop(); } catch {}
        btn.textContent = prev;
        btn.classList.remove('recording');
        btn.removeEventListener('click', stop);
    };
    btn.addEventListener('click', stop);

    rec.onresult = (event) => {
        const text = event.results && event.results[0] && event.results[0][0]
            ? event.results[0][0].transcript : '';
        onResult(text);
    };
    rec.onerror = () => {
        // Auto-fallback to server transcription using WAV recording
        alert('Speech recognition error. Falling back to server transcription.');
        stop();
        startVoiceRecording(async (wavBlob) => {
            try {
                document.getElementById('voice-btn').classList.remove('recording');
                const formData = new FormData();
                formData.append('audio', wavBlob, 'recording.wav');
                const res = await fetch('/api/transcribe', { method: 'POST', body: formData });
                const data = await res.json();
                if (data && data.text) {
                    socket.emit('send_message', { recipient: currentRecipient, message: data.text });
                } else {
                    alert('Transcription failed: ' + (data.error || 'Unknown error'));
                }
            } catch (err) {
                console.error('Voice send error', err);
                alert('Voice message failed.');
            }
        });
    };
    rec.onend = () => {
        stop();
    };

    try {
        rec.start();
        // Safety timeout
        setTimeout(() => stop(), 10000);
    } catch (e) {
        stop();
        alert('Could not start speech recognition.');
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ---- Voice recording (WAV 16k mono) ----
let mediaStream = null;
let audioContext = null;
let processor = null;
let input = null;
let recordedBuffers = [];
let recordingSampleRate = 16000;
let sourceSampleRate = 44100;
let isRecording = false;

async function startVoiceRecording(onComplete) {
    if (isRecording) return;
    try {
        mediaStream = await navigator.mediaDevices.getUserMedia({ audio: true });
        audioContext = new (window.AudioContext || window.webkitAudioContext)();
        sourceSampleRate = audioContext.sampleRate;
        input = audioContext.createMediaStreamSource(mediaStream);
        processor = audioContext.createScriptProcessor(4096, 1, 1);
        recordedBuffers = [];
        isRecording = true;

        processor.onaudioprocess = (e) => {
            if (!isRecording) return;
            const inputData = e.inputBuffer.getChannelData(0);
            // Downsample to 16k and store Int16 samples
            const downsampled = downsampleBuffer(inputData, sourceSampleRate, recordingSampleRate);
            const int16 = floatTo16BitPCM(downsampled);
            recordedBuffers.push(int16);
        };

        input.connect(processor);
        processor.connect(audioContext.destination);

        // Simple UX: toggle button text during recording
        const btn = document.getElementById('voice-btn');
        const prev = btn.textContent;
        btn.textContent = '⏹';
        btn.classList.add('recording');

        // Stop after 10 seconds or on second click
        const stopHandler = async () => {
            btn.removeEventListener('click', stopHandler);
            await stopRecordingInternal(btn, prev, onComplete);
        };
        btn.addEventListener('click', stopHandler);

        setTimeout(async () => {
            if (isRecording) {
                btn.removeEventListener('click', stopHandler);
                await stopRecordingInternal(btn, prev, onComplete);
            }
        }, 10000);
    } catch (err) {
        console.error('Mic access error', err);
        alert('Microphone access denied or unavailable.');
        isRecording = false;
    }
}

async function stopRecordingInternal(btn, prev, onComplete) {
    try {
        isRecording = false;
        processor && processor.disconnect();
        input && input.disconnect();
        mediaStream && mediaStream.getTracks().forEach(t => t.stop());
        audioContext && audioContext.close();
    } catch {}
    btn.textContent = prev;
    btn.classList.remove('recording');

    // Build WAV
    const combined = mergeBuffers(recordedBuffers);
    const wavBlob = encodeWAV(combined, recordingSampleRate);
    onComplete(wavBlob);
}

function downsampleBuffer(buffer, sampleRate, outRate) {
    if (outRate === sampleRate) return buffer;
    const sampleRateRatio = sampleRate / outRate;
    const newLength = Math.round(buffer.length / sampleRateRatio);
    const result = new Float32Array(newLength);
    let offsetResult = 0;
    let offsetBuffer = 0;
    while (offsetResult < result.length) {
        const nextOffsetBuffer = Math.round((offsetResult + 1) * sampleRateRatio);
        let accum = 0, count = 0;
        for (let i = offsetBuffer; i < nextOffsetBuffer && i < buffer.length; i++) {
            accum += buffer[i];
            count++;
        }
        result[offsetResult] = accum / count;
        offsetResult++;
        offsetBuffer = nextOffsetBuffer;
    }
    return result;
}

function floatTo16BitPCM(float32Array) {
    const output = new Int16Array(float32Array.length);
    for (let i = 0; i < float32Array.length; i++) {
        let s = Math.max(-1, Math.min(1, float32Array[i]));
        output[i] = s < 0 ? s * 0x8000 : s * 0x7FFF;
    }
    return output;
}

function mergeBuffers(chunks) {
    let totalLength = 0;
    chunks.forEach(c => totalLength += c.length);
    const result = new Int16Array(totalLength);
    let offset = 0;
    chunks.forEach(c => { result.set(c, offset); offset += c.length; });
    return result;
}

function encodeWAV(samples, sampleRate) {
    const buffer = new ArrayBuffer(44 + samples.length * 2);
    const view = new DataView(buffer);

    /* RIFF identifier */
    writeString(view, 0, 'RIFF');
    /* file length */
    view.setUint32(4, 36 + samples.length * 2, true);
    /* RIFF type */
    writeString(view, 8, 'WAVE');
    /* format chunk identifier */
    writeString(view, 12, 'fmt ');
    /* format chunk length */
    view.setUint32(16, 16, true);
    /* sample format (raw) */
    view.setUint16(20, 1, true);
    /* channel count */
    view.setUint16(22, 1, true);
    /* sample rate */
    view.setUint32(24, sampleRate, true);
    /* byte rate (sample rate * block align) */
    view.setUint32(28, sampleRate * 2, true);
    /* block align (channel count * bytes per sample) */
    view.setUint16(32, 2, true);
    /* bits per sample */
    view.setUint16(34, 16, true);
    /* data chunk identifier */
    writeString(view, 36, 'data');
    /* data chunk length */
    view.setUint32(40, samples.length * 2, true);

    // PCM samples
    let offset = 44;
    for (let i = 0; i < samples.length; i++, offset += 2) {
        view.setInt16(offset, samples[i], true);
    }

    return new Blob([view], { type: 'audio/wav' });
}

function writeString(view, offset, string) {
    for (let i = 0; i < string.length; i++) {
        view.setUint8(offset + i, string.charCodeAt(i));
    }
}


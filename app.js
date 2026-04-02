// E2E Encryption Logic & Chat Application via Global Public MQTT
// Architecture: PBKDF2 for Key Derivation, AES-GCM for Encryption
// 10-Person Multi-User Capable with Auto-Join Share Links

// Unique Identity for this exact instance
const tabId = 'peer_' + Math.random().toString(36).substr(2, 6).toUpperCase();

// Limits
const MAX_PARTICIPANTS = 10;

// Memory mapping of active peers (tabId -> Last Seen Timestamp)
let activePeers = new Map();
activePeers.set(tabId, Date.now()); // Include self immediately

// DOM Elements
const msgInput = document.getElementById('message-input');
const sendBtn = document.getElementById('send-btn');
const messagesContainer = document.getElementById('messages-container');
const roomIdDisplay = document.getElementById('room-id-display');
const brokerStatus = document.getElementById('broker-status');

const headerPeerStatus = document.getElementById('header-peer-status');
const tabIdDisplay = document.getElementById('tab-id-display');

const loginOverlay = document.getElementById('login-overlay');
const roomPasswordInput = document.getElementById('room-password');
const joinBtn = document.getElementById('join-btn');
const shareLinkBtn = document.getElementById('share-link-btn');

const participantsList = document.getElementById('participants-list');
const participantCountHeader = document.getElementById('participant-count-header');

tabIdDisplay.textContent = tabId.replace('peer_', '');

// State Variables
let sharedSecretKey = null;
let roomTopic = null;
let mqttClient = null;

// 0. Auto-Load from Link Share
if (window.location.hash) {
    const hiddenPwd = decodeURIComponent(window.location.hash.substring(1));
    if (hiddenPwd.length >= 4) {
        roomPasswordInput.value = hiddenPwd;
        // Optionally auto-join, but giving the user a chance to click is better UX
    }
}

// 1. Cryptography Functions (PBKDF2 + AES-GCM)
const STATIC_SALT = new TextEncoder().encode("cipherchat-black-salt-multiuser");

async function setupCryptoEnvironment(password) {
    const encoder = new TextEncoder();
    const passwordBytes = encoder.encode(password);

    // Hash the password for the Room ID
    const hashBuffer = await crypto.subtle.digest('SHA-256', passwordBytes);
    roomTopic = "cipherchat/stealth/" + BufferToHex(new Uint8Array(hashBuffer)).substring(0, 16);
    roomIdDisplay.textContent = roomTopic.split('/').pop();

    // Import password via PBKDF2
    const keyMaterial = await crypto.subtle.importKey(
        "raw", passwordBytes, { name: "PBKDF2" }, false, ["deriveKey"]
    );

    // Derive AES-GCM 256 Key
    sharedSecretKey = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: STATIC_SALT, iterations: 100000, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true, ["encrypt", "decrypt"]
    );
}

async function encryptMessage(text) {
    const encoded = new TextEncoder().encode(text);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, sharedSecretKey, encoded
    );
    return {
        ciphertext: Array.from(new Uint8Array(ciphertext)),
        iv: Array.from(iv)
    };
}

async function decryptMessage(encryptedObj) {
    const ciphertext = new Uint8Array(encryptedObj.ciphertext);
    const iv = new Uint8Array(encryptedObj.iv);
    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv }, sharedSecretKey, ciphertext
    );
    return new TextDecoder().decode(decrypted);
}

// 2. Networking via Public MQTT
function connectToBroker() {
    brokerStatus.textContent = "Connecting...";
    
    mqttClient = mqtt.connect('wss://broker.hivemq.com:8884/mqtt', {
        clientId: tabId
    });

    mqttClient.on('connect', () => {
        brokerStatus.textContent = "Connected";
        brokerStatus.style.color = "var(--success)";
        
        mqttClient.subscribe(roomTopic, (err) => {
            if (!err) {
                showToast("Joined secure environment!", "success");
                updateConnectionUI(true);
                broadcastPresence();
            } else {
                showToast("Failed to subscribe to room", "error");
            }
        });
    });

    mqttClient.on('message', async (topic, message) => {
        if (topic !== roomTopic) return;
        
        try {
            const data = JSON.parse(message.toString());
            
            // Register or update peer presence
            if (data.tabId && data.tabId !== tabId) {
                if (!activePeers.has(data.tabId)) {
                    if (activePeers.size >= MAX_PARTICIPANTS) {
                        console.warn("Room capacity reached.");
                        return; // Ignore new peers if full
                    }
                    showToast(`Peer ${data.tabId.substr(5)} joined.`, "info");
                    // We respond to announce ourselves back to the newcomer
                    setTimeout(broadcastPresence, 1000); 
                }
                activePeers.set(data.tabId, Date.now());
                renderParticipantsList();
            }

            if (data.tabId === tabId) return; // Prevent echoing my own messages

            if (data.type === 'CHAT_MESSAGE') {
                if (!sharedSecretKey) return;
                try {
                    const decryptedText = await decryptMessage(data.encryptedObj);
                    const cipherHex = BufferToHex(new Uint8Array(data.encryptedObj.ciphertext));
                    appendMessage(decryptedText, 'received', cipherHex, data.tabId);
                } catch (err) {
                    console.error("Decryption failed. Wrong password?", err);
                }
            }
        } catch(e) { } // Ignore malformed JSON naturally
    });
}

function broadcastPresence() {
    if (!mqttClient) return;
    mqttClient.publish(roomTopic, JSON.stringify({ type: 'PRESENCE', tabId: tabId }));
}

// Ping presence every 15 seconds to keep alive in participant list
setInterval(() => {
    if (sharedSecretKey) broadcastPresence();
}, 15000);

// Prune inactive peers (no ping for 45s)
setInterval(() => {
    const now = Date.now();
    let changed = false;
    activePeers.forEach((lastSeen, peerId) => {
        if (peerId !== tabId && now - lastSeen > 45000) {
            activePeers.delete(peerId);
            changed = true;
        }
    });
    if(changed) renderParticipantsList();
}, 5000);

// 3. UI Interactions

joinBtn.addEventListener('click', async () => {
    const pwd = roomPasswordInput.value;
    if (pwd.length < 4) {
        showToast("Password must be at least 4 characters", "info");
        return;
    }
    
    joinBtn.disabled = true;
    joinBtn.innerHTML = 'Joining...';

    try {
        await setupCryptoEnvironment(pwd);
        loginOverlay.classList.add('hidden');
        // Update URL to preserve password hash so refreshing keeps them in
        window.history.replaceState(null, null, `#${encodeURIComponent(pwd)}`);
        connectToBroker();
    } catch(err) {
        showToast("Failed to initialize cryptography.", "error");
        joinBtn.disabled = false;
    }
});

roomPasswordInput.addEventListener('keypress', (e) => {
    if(e.key === 'Enter') joinBtn.click();
});

shareLinkBtn.addEventListener('click', () => {
    const pwd = roomPasswordInput.value || decodeURIComponent(window.location.hash.substring(1));
    const link = `${window.location.origin}${window.location.pathname}#${encodeURIComponent(pwd)}`;
    navigator.clipboard.writeText(link).then(() => {
        showToast("Shareable Link Copied!", "success");
    }).catch(() => {
        showToast("Failed to copy link.", "error");
    });
});

function renderParticipantsList() {
    const count = activePeers.size;
    participantCountHeader.textContent = `Participants (${count}/${MAX_PARTICIPANTS})`;
    
    if (count > 1) {
        headerPeerStatus.textContent = `${count - 1} peers connected`;
        headerPeerStatus.classList.add('text-online');
    } else {
        headerPeerStatus.textContent = `Waiting for others...`;
        headerPeerStatus.classList.remove('text-online');
    }

    participantsList.innerHTML = '';
    
    activePeers.forEach((lastSeen, peerId) => {
        const isMe = peerId === tabId;
        const colorSeed = parseInt(peerId.replace('peer_', ''), 36) || 0;
        // Generate a deterministic dark hue for each participant
        const bg = isMe ? '#555' : `hsl(${colorSeed % 360}, 40%, 30%)`;

        const li = document.createElement('li');
        li.className = 'participant-item';
        li.innerHTML = `
            <div class="p-avatar" style="background: ${bg}"></div>
            <span>${isMe ? 'You' : 'Peer ' + peerId.substr(5)}</span>
        `;
        participantsList.appendChild(li);
    });
}

function updateConnectionUI(isConnected) {
    msgInput.disabled = !isConnected;
    sendBtn.disabled = !isConnected;
    
    if (isConnected) {
        msgInput.placeholder = "Type a secure message...";
        renderParticipantsList();
    }
}

async function handleSendMessage() {
    if (activePeers.size > MAX_PARTICIPANTS) {
        showToast("Room is full. Cannot send.", "error");
        return;
    }

    const text = msgInput.value.trim();
    if (!text || !sharedSecretKey || !mqttClient) return;
    
    msgInput.value = '';
    
    try {
        const encryptedObj = await encryptMessage(text);
        
        mqttClient.publish(roomTopic, JSON.stringify({
            type: 'CHAT_MESSAGE',
            tabId: tabId,
            encryptedObj: encryptedObj
        }));
        
        const cipherHex = BufferToHex(new Uint8Array(encryptedObj.ciphertext));
        appendMessage(text, 'sent', cipherHex, tabId);
        
    } catch(err) {
        showToast("Encryption failed", "error");
    }
}

function appendMessage(text, type, cipherHex = '', senderId = '') {
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const isSent = type === 'sent';
    
    const wrapper = document.createElement('div');
    wrapper.className = `message message-${type} show-encryption`;
    
    let peerLabel = '';
    if (!isSent && senderId) {
        peerLabel = `<span class="peer-indicator">Peer ${senderId.substr(5)}</span>`;
    }

    wrapper.innerHTML = `
        <div class="message-bubble">
            ${peerLabel}
            <div class="encrypted-text" title="Encrypted Payload">${cipherHex.substring(0, 20)}...</div>
            <div class="plain-text">${text}</div>
            <div class="message-meta">
                <span class="time">${time}</span>
                ${isSent ? '<i class="ph ph-check-circle message-status"></i>' : ''}
            </div>
        </div>
    `;
    
    messagesContainer.appendChild(wrapper);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function BufferToHex(buffer) {
    return Array.from(buffer).map(b => b.toString(16).padStart(2, '0')).join('');
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icon = type === 'success' ? 'ph-check-circle' : type === 'error' ? 'ph-warning-circle' : 'ph-info';
    toast.innerHTML = `<i class="ph ${icon}"></i><span>${message}</span>`;
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'fadeOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Events
sendBtn.addEventListener('click', handleSendMessage);
msgInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleSendMessage();
});

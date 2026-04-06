/**
 * E2EE Chat Client Logic
 * Xử lý: key exchange (DH), encryption/decryption, messaging
 * (Auth logic đã chuyển sang auth.js / login.html)
 */

const socket = io();

// State
let clientState = {
  userId: null,
  username: null,
  privateKey: null,
  publicKey: null,
  selectedUser: null,
  pendingKeyExchanges: {}, // userId -> {privateKey, publicKey}
  sessions: {}, // sessionId -> {publicKeyA, publicKeyB, encKey, decKey, counter}
  messages: [] // Lưu tin nhắn hiển thị
};

// ========== INIT ON PAGE LOAD ==========
document.addEventListener('DOMContentLoaded', async () => {
  
  // Lấy info từ sessionStorage (per tab)
  const userId = sessionStorage.getItem('userId');
  const username = sessionStorage.getItem('username');
  
  if (!userId || !username) {
    window.location.href = '/login';
    return;
  }
  
  clientState.userId = userId;
  clientState.username = username;
  
  // Authenticate socket với server
  socket.emit('authenticate', { userId, username });
  
  // Khởi tạo crypto
  try {
    await initializeCrypto();
    initializeChatUI();
  } catch (e) {
    alert('Lỗi khởi tạo: ' + e.message);
    window.location.href = '/login';
  }
});

// ========== UI INIT ==========

function initializeChatUI() {
  // Hiển thị thông tin user
  document.getElementById('userInfo').textContent = `👤 ${clientState.username}`;
  
  // Yêu cầu danh sách user
  socket.emit('requestUserList');
  
  // Attach event listener cho message input
  const messageInput = document.getElementById('messageInput');
  if (messageInput) {
    messageInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleSendMessage();
      }
    });
  }
}

function handleLogout() {
  if (confirm('Bạn chắc chứ?')) {
    sessionStorage.removeItem('userId');
    sessionStorage.removeItem('username');
    window.location.href = '/login';
  }
}

// Danh sách user cập nhật
socket.on('userList', (userList) => {
  updateUserList(userList);
});

socket.on('userListUpdate', (userList) => {
  updateUserList(userList);
});

// Xác thực socket (khi refresh page)
socket.on('authenticateSuccess', (data) => {
});

// Nhận yêu cầu key exchange từ đối phương
socket.on('keyExchangeRequest', async (data) => {
  
  const { fromUserId, fromUsername, publicKey, sessionId } = data;
  
  // Tự động chấp nhận (trong thực tế có thể hỏi user)
  const keyPair = await generateECDH();
  
  // Lưu key pair cho key exchange này
  clientState.pendingKeyExchanges[fromUserId] = {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey
  };
  
  socket.emit('acceptKeyExchange', {
    sessionId,
    publicKey: keyPair.publicKey
  });
  
  // Setup session tạm thời (fingerprint sẽ được update khi nhận sessionEstablished)
  await setupSession(sessionId, fromUserId, publicKey, keyPair.privateKey, null);
  
  // 🆕 Auto-select user để B có thể gửi tin nhắn
  clientState.selectedUser = fromUserId;
  document.getElementById('chatTitle').textContent = `Chat with ${fromUsername}`;
  document.getElementById('messages').innerHTML = '';
  clientState.messages = [];
  document.getElementById('inputArea').style.display = 'flex';
  document.getElementById('messageInput').focus();
  
  updateUserListUI();
  
  // Xóa pending key sau khi dùng
  delete clientState.pendingKeyExchanges[fromUserId];
});

// Helper: update user list UI to show active selection
function updateUserListUI() {
  // Fetch current user list and re-render with updated selection
  const userListDiv = document.getElementById('userList');
  
  // Get all users from DOM
  const userItems = document.querySelectorAll('.user-item');
  userItems.forEach(item => {
    const userId = item.getAttribute('data-userid');
    if (userId === clientState.selectedUser) {
      item.classList.add('active');
    } else {
      item.classList.remove('active');
    }
  });
}

// Nhận phản hồi key exchange từ đối phương
socket.on('keyExchangeAccepted', async (data) => {
  
  const { sessionId, publicKey, fingerprint } = data;
  
  // Lấy private key từ pending (người initiate)
  const pendingKey = clientState.pendingKeyExchanges[data.fromUserId];
  if (!pendingKey) {
    return;
  }
  
  // Tính toán shared secret và setup session (dùng fingerprint từ server)
  await setupSession(sessionId, data.fromUserId, publicKey, pendingKey.privateKey, fingerprint);
  
  // Xóa pending key sau khi dùng
  delete clientState.pendingKeyExchanges[data.fromUserId];
});

// Nhận confirmation từ server sau khi establish session (responder side)
socket.on('sessionEstablished', (data) => {
  const { sessionId, fingerprint } = data;
  
  // Update fingerprint trong session
  if (clientState.sessions[sessionId]) {
    clientState.sessions[sessionId].peerFingerprint = fingerprint;
    updateKeyStatus(true, fingerprint);
    
    // Hiển thị thông báo verify
    addMessageToUI({
      text: `Bảo mật thành công\n Fingerprint: ${fingerprint}\n\n Hãy xác nhận fingerprint này với đối phương qua ngoài app để bảo mật cuộc trò chuyện!`,
      sender: 'system',
      timestamp: new Date().toISOString()
    });
  }
});

// Nhận tin nhắn được mã hóa
socket.on('receiveMessage', async (data) => {
  
  const { sessionId, senderId, ciphertext, nonce, counter, timestamp } = data;
  
  try {
    const session = clientState.sessions[sessionId];
    if (!session) {
      return;
    }

    // Kiểm tra counter (chống replay)
    if (counter <= session.lastCounter) {
      return;
    }

    // Giải mã
    const aad = JSON.stringify({ sessionId, senderId, counter });
    const plaintext = await decryptMessage(session.decKey, ciphertext, nonce, aad);
    
    session.lastCounter = counter;

    // Thêm tin nhắn vào UI
    addMessageToUI({
      text: plaintext,
      sender: 'other',
      counter,
      timestamp
    });

  } catch (e) {
    addMessageToUI({
      text: '[ERROR] Không thể giải mã tin nhắn (khóa sai hoặc tin bị sửa)',
      sender: 'system',
      timestamp: new Date().toISOString()
    });
  }
});

// ========== UI FUNCTIONS ==========

function updateUserList(userList) {
  const userListDiv = document.getElementById('userList');
  
  if (userList.length === 0) {
    userListDiv.innerHTML = '<div class="placeholder">Chưa có user khác</div>';
    return;
  }

  userListDiv.innerHTML = userList.map(user => {
    const classes = ['user-item', user.online ? 'online' : '', clientState.selectedUser === user.userId ? 'active' : ''].filter(Boolean).join(' ');
    return `
    <div class="${classes}" data-userid="${user.userId}" onclick="selectUser('${user.userId}', '${user.username}')">
      ${user.username}
      <div class="status">${user.online ? 'Online' : 'Offline'}</div>
    </div>
  `;
  }).join('');
}

function selectUser(userId, username) {
  clientState.selectedUser = userId;
  document.getElementById('chatTitle').textContent = `Chat with ${username}`;
  document.getElementById('messages').innerHTML = '';
  clientState.messages = [];
  document.getElementById('inputArea').style.display = 'flex';
  document.getElementById('messageInput').focus();
  
  // Kiểm tra xem đã setup session chưa
  const existingSession = Object.keys(clientState.sessions).find(sid => 
    clientState.sessions[sid].peerId === userId
  );
  
  if (existingSession) {
    updateKeyStatus(true);
  } else {
    // Bắt đầu key exchange
    initiateKeyExchange(userId);
    updateKeyStatus(false);
  }

  // Update active user
  document.querySelectorAll('.user-item').forEach(item => {
    item.classList.remove('active');
  });
  event.target.closest('.user-item').classList.add('active');
}

async function handleSendMessage() {
  const messageInput = document.getElementById('messageInput');
  const plaintext = messageInput.value.trim();
  
  if (!plaintext) return;
  if (!clientState.selectedUser) {
    alert('Chọn người để chat');
    return;
  }

  // Tìm session theo peerId (selectedUser)
  const sessionId = Object.keys(clientState.sessions).find(sid => 
    clientState.sessions[sid].peerId === clientState.selectedUser
  );

  if (!sessionId) {
    alert('Phiên chat chưa bảo mật. Vui lòng chờ key exchange hoàn tất');
    return;
  }

  const session = clientState.sessions[sessionId];
  
  // Tạo counter
  session.counter = (session.counter || 0) + 1;
  
  // Mã hóa
  const aad = JSON.stringify({ sessionId, senderId: clientState.userId, counter: session.counter });
  const encrypted = await encryptMessage(session.encKey, plaintext, aad);

  // Gửi qua server
  socket.emit('sendMessage', {
    sessionId,
    recipientId: clientState.selectedUser,
    ciphertext: encrypted.ciphertext,
    nonce: encrypted.nonce,
    counter: session.counter
  });

  // Hiển thị tin nhắn riêng
  addMessageToUI({
    text: plaintext,
    sender: 'own',
    counter: session.counter,
    timestamp: new Date().toISOString()
  });

  messageInput.value = '';
}

function addMessageToUI(message) {
  const messagesDiv = document.getElementById('messages');
  
  // Clear placeholder nếu có
  if (messagesDiv.querySelector('.no-user-selected')) {
    messagesDiv.innerHTML = '';
  }

  const time = new Date(message.timestamp).toLocaleTimeString('vi-VN');
  const messageEl = document.createElement('div');
  messageEl.className = `message ${message.sender}`;
  
  // Thêm counter para message (chứ không phải system)
  let counterText = '';
  if (message.sender !== 'system' && message.counter) {
    counterText = `<div class="message-counter">#${message.counter}</div>`;
  }
  
  messageEl.innerHTML = `
    ${message.text}
    ${counterText}
    <div class="message-time">${time}</div>
  `;
  
  messagesDiv.appendChild(messageEl);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function updateKeyStatus(secured, fingerprint = null) {
  const statusDiv = document.getElementById('keyStatus');
  statusDiv.className = `key-status ${secured ? 'secured' : 'unsecured'}`;
  
  if (secured && fingerprint) {
    statusDiv.innerHTML = `
      <span class="status-dot green"></span>
      <span> Bảo mật | Key: ${fingerprint}</span>
    `;
  } else if (secured) {
    statusDiv.innerHTML = `
      <span class="status-dot green"></span>
      <span> Bảo mật</span>
    `;
  } else {
    statusDiv.innerHTML = `
      <span class="status-dot red"></span>
      <span> Chưa bảo mật</span>
    `;
  }
}

// ========== CRYPTO FUNCTIONS ==========

/**
 * Tính fingerprint (hash) của public key để verify
 */
async function getPublicKeyFingerprint(publicKeyJwk) {
  try {
    const keyString = JSON.stringify(publicKeyJwk);
    const encoder = new TextEncoder();
    const data = encoder.encode(keyString);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex.substring(0, 16).toUpperCase();  // Shortened to 16 chars
  } catch (e) {
    return 'ERROR';
  }
}

/**
 * Khởi tạo cặp khóa ECDH cho client
 */
async function initializeCrypto() {
  try {
    console.log('[INIT CRYPTO]');
    const keyPair = await generateECDH();
    clientState.privateKey = keyPair.privateKey;
    clientState.publicKey = keyPair.publicKey;
    console.log('[OK] Crypto initialized\n');
    return true;
  } catch (e) {
    console.error('[ERROR] Crypto init:', e.message, e);
    throw new Error('Không thể khởi tạo crypto: ' + e.message);
  }
}

/**
 * Tạo cặp khóa ECDH P-256
 */
async function generateECDH() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256"
    },
    true,
    ["deriveKey"]
  );

  const publicKeyJwk = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privateKeyJwk = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);

  console.log('[MY PRIVATE KEY] generated (secret, kept locally)');
  console.log('[MY PUBLIC KEY] generated (send to peer)');

  return {
    privateKey: JSON.stringify(privateKeyJwk),
    publicKey: JSON.stringify(publicKeyJwk)
  };
}

/**
 * Bắt đầu quá trình trao đổi khóa (initiate)
 */
async function initiateKeyExchange(targetUserId) {
  const keyPair = await generateECDH();
  
  // Lưu key pair cho key exchange này
  clientState.pendingKeyExchanges[targetUserId] = {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey
  };
  
  socket.emit('initiateKeyExchange', {
    targetUserId,
    publicKey: keyPair.publicKey
  });
}

/**
 * Setup session sau khi trao đổi khóa thành công
 */
async function setupSession(sessionId, peerId, peerPublicKeyJwk, myPrivateKey, serverFingerprint = null) {
  try {
    console.log('[SESSION] Setting up...');
    
    // Tính shared secret từ ECDH
    const sharedSecret = await computeECDHSecret(myPrivateKey, peerPublicKeyJwk);
    
    // Dùng fingerprint từ server (đã đồng bộ), hoặc tính lại nếu không có
    let peerFingerprint = serverFingerprint;
    if (!peerFingerprint) {
      peerFingerprint = await getPublicKeyFingerprint(peerPublicKeyJwk);
    }
    
    // Derive session keys từ shared secret (với userId để xác định send/recv)
    const keys = await deriveSessionKeys(sharedSecret, sessionId, clientState.userId, peerId);
    console.log('[KEYS] Enc: ' + keys.encKey.substring(0, 8) + '... | Dec: ' + keys.decKey.substring(0, 8) + '...');
    
    // Lưu session
    clientState.sessions[sessionId] = {
      peerId,
      encKey: keys.encKey,
      decKey: keys.decKey,
      counter: 0,
      lastCounter: -1,
      peerFingerprint
    };
    
    console.log('[SESSION] Ready: ' + sessionId.substring(0, 12) + '...');
    
    // Chỉ update UI nếu đã có fingerprint từ server
    if (serverFingerprint) {
      updateKeyStatus(true, peerFingerprint);
      
      // Hiển thị thông báo verify
      addMessageToUI({
        text: `Bảo mật thành công\n[KEY] Fingerprint: ${peerFingerprint}\n\nHãy xác nhận fingerprint này với đối phương qua ngoài app để bảo mật cuộc trò chuyện!`,
        sender: 'system',
        timestamp: new Date().toISOString()
      });
    } else {
      // Fingerprint sẽ được update khi nhận từ server
      updateKeyStatus(false);
    }
    
    return true;
    
  } catch (e) {
    console.error('[ERROR] Setup session:', e.message, e.stack);
    addMessageToUI({
      text: 'Lỗi: Không thể setup phiên bảo mật: ' + e.message,
      sender: 'system',
      timestamp: new Date().toISOString()
    });
    return false;
  }
}

/**
 * Tính ECDH shared secret
 * (Web Crypto API - P-256 ECDH)
 */
async function computeECDHSecret(myPrivateKeyJwk, peerPublicKeyJwk) {
  try {
    const myPrivateKey = await window.crypto.subtle.importKey(
      "jwk",
      JSON.parse(myPrivateKeyJwk),
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey"]
    );

    const peerPubKeyObj = JSON.parse(peerPublicKeyJwk);
    const peerPublicKey = await window.crypto.subtle.importKey(
      "jwk",
      peerPubKeyObj,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );

    // Derive shared secret
    const sharedSecret = await window.crypto.subtle.deriveKey(
      { name: "ECDH", public: peerPublicKey },
      myPrivateKey,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    // Export thành raw bytes
    const rawSecret = await window.crypto.subtle.exportKey("raw", sharedSecret);
    const secretB64 = btoa(String.fromCharCode(...new Uint8Array(rawSecret)));
    
    console.log('[ECDH] Shared Secret K:', secretB64.substring(0, 12) + '...');
    
    return secretB64;
    
  } catch (e) {
    console.error('[ERROR] ECDH failed');
    throw e;
  }
}

/**
 * Derive session keys từ shared secret
 * (Web Crypto API HKDF đơn giản)
 */
async function deriveSessionKeys(sharedSecretB64, salt, clientUserId, peerUserId) {
  try {
    const sharedSecret = Uint8Array.from(atob(sharedSecretB64), c => c.charCodeAt(0));
    
    // HKDF simple version
    // PRK = HMAC(salt, sharedSecret)
    const hmacKey = await window.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(salt || ""),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const prk = await window.crypto.subtle.sign(
      "HMAC",
      hmacKey,
      sharedSecret
    );

    // Expand - tạo 2 keys tách rời (mỗi key 32 bytes = 256 bits)
    const hmacKey2 = await window.crypto.subtle.importKey(
      "raw",
      prk,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    // Key 1 và Key 2 (thứ tự không quan trọng)
    const key1Bytes = await window.crypto.subtle.sign(
      "HMAC",
      hmacKey2,
      new TextEncoder().encode("E2EE_CHAT_KEY_1")
    );

    const key2Bytes = await window.crypto.subtle.sign(
      "HMAC",
      hmacKey2,
      new TextEncoder().encode("E2EE_CHAT_KEY_2")
    );

    const key1 = btoa(String.fromCharCode(...new Uint8Array(key1Bytes)));
    const key2 = btoa(String.fromCharCode(...new Uint8Array(key2Bytes)));

    // Xác định encKey và decKey dựa trên userId
    let encKey, decKey;
    if (clientUserId < peerUserId) {
      encKey = key1;
      decKey = key2;
    } else {
      encKey = key2;
      decKey = key1;
    }

    console.log('[DERIVE KEYS]', encKey.substring(0, 8) + '...' + ' | ' + decKey.substring(0, 8) + '...');

    return { encKey, decKey };
    
  } catch (e) {
    console.error('[ERROR] Derive keys error:', e);
    throw e;
  }
}

/**
 * Mã hóa tin nhắn AES-256-GCM
 */
async function encryptMessage(keyB64, plaintext, aad) {
  try {
    // Import key
    const keyArray = Uint8Array.from(atob(keyB64), c => c.charCodeAt(0));
    const key = await window.crypto.subtle.importKey(
      "raw",
      keyArray,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );

    // Tạo nonce (12 bytes)
    const nonce = window.crypto.getRandomValues(new Uint8Array(12));
    const nonceHex = Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join('');

    console.log('\n[ENCRYPT] Plaintext: "' + plaintext + '"');

    // Mã hóa - GCM output bao gồm ciphertext + tag (16 bytes)
    const ciphertextWithTag = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: new TextEncoder().encode(aad) },
      key,
      new TextEncoder().encode(plaintext)
    );

    const cipherHex = Array.from(new Uint8Array(ciphertextWithTag))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    console.log('[ENCRYPT] Ciphertext:', cipherHex.substring(0, 16) + '...\n');

    return {
      ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertextWithTag))),
      nonce: btoa(String.fromCharCode(...nonce))
    };
    
  } catch (e) {
    console.error('[ERROR] Encrypt failed');
    throw e;
  }
}

/**
 * Giải mã tin nhắn AES-256-GCM
 */
async function decryptMessage(keyB64, ciphertextB64, nonceB64, aad) {
  try {
    // Import key
    const keyArray = Uint8Array.from(atob(keyB64), c => c.charCodeAt(0));
    const key = await window.crypto.subtle.importKey(
      "raw",
      keyArray,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    // Reconstruct từ ciphertext + tag (ghép nối trong base64)
    const ciphertextWithTag = Uint8Array.from(atob(ciphertextB64), c => c.charCodeAt(0));
    const nonce = Uint8Array.from(atob(nonceB64), c => c.charCodeAt(0));
    const nonceHex = Array.from(nonce).map(b => b.toString(16).padStart(2, '0')).join('');
    const cipherHex = Array.from(ciphertextWithTag).map(b => b.toString(16).padStart(2, '0')).join('');

    console.log('[DECRYPT] Ciphertext:', cipherHex.substring(0, 16) + '...');

    // Giải mã
    const plaintext = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: new TextEncoder().encode(aad) },
      key,
      ciphertextWithTag
    );

    const decryptedText = new TextDecoder().decode(plaintext);
    console.log('[DECRYPT] Plaintext: "' + decryptedText + '"\n');
    
    return decryptedText;
    
  } catch (e) {
    console.error('[ERROR] Decrypt failed');
    throw new Error('Giải mã thất bại: ' + e.message);
  }
}

console.log('[Client] E2EE Chat loaded');

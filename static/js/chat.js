/**
 * E2EE Chat Client Logic
 * Xử lý: auth, key exchange (DH), encryption/decryption
 */

const socket = io();

// State
let clientState = {
  userId: null,
  username: null,
  privateKey: null,
  publicKey: null,
  selectedUser: null,
  sessions: {}, // sessionId -> {publicKeyA, publicKeyB, encKey, decKey, counter}
  messages: [] // Lưu tin nhắn hiển thị
};

// ========== AUTH ==========
function handleRegister() {
  const username = document.getElementById('usernameInput').value.trim();
  const password = document.getElementById('passwordInput').value.trim();
  
  if (!username || !password) {
    showAuthError('Vui lòng nhập username và password');
    return;
  }

  socket.emit('register', { username, password });
}

function handleLogin() {
  const username = document.getElementById('usernameInput').value.trim();
  const password = document.getElementById('passwordInput').value.trim();
  
  if (!username || !password) {
    showAuthError('Vui lòng nhập username và password');
    return;
  }

  socket.emit('login', { username, password });
}

function handleLogout() {
  if (confirm('Bạn chắc chứ?')) {
    location.reload();
  }
}

function showAuthError(message) {
  const errorDiv = document.getElementById('authError');
  errorDiv.textContent = message;
  errorDiv.style.display = 'block';
  setTimeout(() => {
    errorDiv.style.display = 'none';
  }, 3000);
}

// ========== SOCKET EVENTS ==========

socket.on('registerSuccess', (data) => {
  console.log('✅ Register successful:', data);
  clientState.userId = data.userId;
  clientState.username = data.username;
  initializeCrypto();
  switchToChatScreen();
});

socket.on('loginSuccess', (data) => {
  console.log('✅ Login successful:', data);
  clientState.userId = data.userId;
  clientState.username = data.username;
  initializeCrypto();
  switchToChatScreen();
});

socket.on('error', (message) => {
  console.error('❌ Server error:', message);
  showAuthError(message);
});

// Danh sách user cập nhật
socket.on('userList', (userList) => {
  updateUserList(userList);
});

socket.on('userListUpdate', (userList) => {
  updateUserList(userList);
});

// Nhận yêu cầu key exchange từ đối phương
socket.on('keyExchangeRequest', async (data) => {
  console.log('🔐 Key exchange request từ:', data.fromUsername);
  
  const { fromUserId, fromUsername, publicKey, sessionId } = data;
  
  // Tự động chấp nhận (trong thực tế có thể hỏi user)
  const keyPair = await generateECDH();
  socket.emit('acceptKeyExchange', {
    sessionId,
    publicKey: keyPair.publicKey
  });
  
  // Lưu session đã trao đổi khóa
  await setupSession(sessionId, fromUserId, publicKey, keyPair.privateKey);
});

// Nhận phản hồi key exchange từ đối phương
socket.on('keyExchangeAccepted', async (data) => {
  console.log('✅ Key exchange accepted từ:', data.fromUserId);
  
  const { sessionId, publicKey } = data;
  
  // Tính toán shared secret và setup session
  // Lấy private key của A (người initiate)
  await setupSession(sessionId, data.fromUserId, publicKey, clientState.privateKey);
});

// Nhận tin nhắn được mã hóa
socket.on('receiveMessage', async (data) => {
  console.log('💬 Nhận tin nhắn từ:', data.senderId);
  
  const { sessionId, senderId, ciphertext, nonce, tag, counter, timestamp } = data;
  
  try {
    const session = clientState.sessions[sessionId];
    if (!session) {
      console.error('❌ Session không tồn tại:', sessionId);
      return;
    }

    // Kiểm tra counter (chống replay)
    if (counter <= session.lastCounter) {
      console.warn('⚠️ Tin nhắn cũ hoặc trùng counter');
      return;
    }

    // Giải mã
    const aad = JSON.stringify({ sessionId, senderId, counter });
    const plaintext = decryptMessage(session.decKey, ciphertext, nonce, tag, aad);
    
    session.lastCounter = counter;

    // Thêm tin nhắn vào UI
    addMessageToUI({
      text: plaintext,
      sender: 'other',
      timestamp
    });

  } catch (e) {
    console.error('❌ Giải mã thất bại:', e.message);
    addMessageToUI({
      text: '❌ Lỗi: Không thể giải mã tin nhắn (khóa sai hoặc tin bị sửa)',
      sender: 'system',
      timestamp: new Date().toISOString()
    });
  }
});

// ========== UI FUNCTIONS ==========

function switchToChatScreen() {
  document.getElementById('authScreen').style.display = 'none';
  document.getElementById('chatScreen').style.display = 'flex';
  
  // Hiển thị thông tin user
  document.getElementById('userInfo').textContent = `👤 ${clientState.username}`;
  
  // Yêu cầu danh sách user
  socket.emit('requestUserList');
}

function updateUserList(userList) {
  const userListDiv = document.getElementById('userList');
  
  if (userList.length === 0) {
    userListDiv.innerHTML = '<div class="placeholder">Chưa có user khác</div>';
    return;
  }

  userListDiv.innerHTML = userList.map(user => `
    <div class="user-item ${user.online ? 'online' : ''} ${clientState.selectedUser === user.userId ? 'active' : ''}" onclick="selectUser('${user.userId}', '${user.username}')">
      ${user.username}
      <div class="status">${user.online ? '🟢 Online' : '🔴 Offline'}</div>
    </div>
  `).join('');
}

function selectUser(userId, username) {
  clientState.selectedUser = userId;
  document.getElementById('chatTitle').textContent = `💬 Chat với ${username}`;
  document.getElementById('messages').innerHTML = '';
  clientState.messages = [];
  document.getElementById('inputArea').style.display = 'flex';
  document.getElementById('messageInput').focus();
  
  // Kiểm tra xem đã setup session chưa
  const sessionId = `${clientState.userId}-${userId}-*`; // Kiểm tra pattern
  const existingSession = Object.keys(clientState.sessions).find(sid => 
    sid.includes(clientState.userId) && sid.includes(userId)
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

function handleSendMessage() {
  const messageInput = document.getElementById('messageInput');
  const plaintext = messageInput.value.trim();
  
  if (!plaintext) return;
  if (!clientState.selectedUser) {
    alert('Chọn người để chat');
    return;
  }

  const sessionId = Object.keys(clientState.sessions).find(sid =>
    sid.includes(clientState.userId) && sid.includes(clientState.selectedUser)
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
  const encrypted = encryptMessage(session.encKey, plaintext, aad);

  // Gửi qua server
  socket.emit('sendMessage', {
    sessionId,
    recipientId: clientState.selectedUser,
    ciphertext: encrypted.ciphertext,
    nonce: encrypted.nonce,
    tag: encrypted.tag,
    counter: session.counter
  });

  // Hiển thị tin nhắn riêng
  addMessageToUI({
    text: plaintext,
    sender: 'own',
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
  messageEl.innerHTML = `
    ${message.text}
    <div class="message-time">${time}</div>
  `;
  
  messagesDiv.appendChild(messageEl);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function updateKeyStatus(secured) {
  const statusDiv = document.getElementById('keyStatus');
  statusDiv.className = `key-status ${secured ? 'secured' : 'unsecured'}`;
  statusDiv.innerHTML = `
    <span class="status-dot ${secured ? 'green' : 'red'}"></span>
    <span>${secured ? '🔒 Bảo mật' : '🔓 Chưa bảo mật'}</span>
  `;
}

// ========== CRYPTO FUNCTIONS ==========

/**
 * Khởi tạo cặp khóa ECDH cho client
 */
async function initializeCrypto() {
  try {
    const keyPair = await generateECDH();
    clientState.privateKey = keyPair.privateKey;
    clientState.publicKey = keyPair.publicKey;
    console.log('✅ Crypto initialized');
  } catch (e) {
    console.error('❌ Crypto init error:', e);
  }
}

/**
 * Tạo cặp khóa ECDH
 * (Node.js crypto module)
 */
async function generateECDH() {
  // Vì là frontend (browser), không dùng Node.js crypto được
  // Cần dùng Web Crypto API hoặc thư viện khác
  // TẠM THỜI: Simulate bằng cách tạo random key
  
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256"
    },
    true, // extractable
    ["deriveKey"]
  );

  // Export public key thành JWK hoặc bytes
  const publicKeyJwk = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privateKeyJwk = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);

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
  socket.emit('initiateKeyExchange', {
    targetUserId,
    publicKey: keyPair.publicKey
  });
  
  // Lưu private key tạm thời
  clientState.privateKey = keyPair.privateKey;
}

/**
 * Setup session sau khi trao đổi khóa thành công
 */
async function setupSession(sessionId, peerId, peerPublicKey, myPrivateKey) {
  try {
    // Tính shared secret từ ECDH
    const sharedSecret = await computeECDHSecret(myPrivateKey, peerPublicKey);
    
    // Derive session keys từ shared secret
    const keys = await deriveSessionKeys(sharedSecret, sessionId);
    
    // Lưu session
    clientState.sessions[sessionId] = {
      peerId,
      encKey: keys.encKey,
      decKey: keys.decKey,
      counter: 0,
      lastCounter: -1
    };
    
    console.log('✅ Session setup:', sessionId);
    updateKeyStatus(true);
    
  } catch (e) {
    console.error('❌ Setup session error:', e);
  }
}

/**
 * Tính ECDH shared secret
 * (Web Crypto API)
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

    const peerPublicKey = await window.crypto.subtle.importKey(
      "jwk",
      JSON.parse(peerPublicKeyJwk),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );

    // Derive shared secret (sử dụng HKDF)
    const sharedSecret = await window.crypto.subtle.deriveKey(
      { name: "ECDH", public: peerPublicKey },
      myPrivateKey,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    // Export thành raw bytes
    const rawSecret = await window.crypto.subtle.exportKey("raw", sharedSecret);
    return btoa(String.fromCharCode(...new Uint8Array(rawSecret)));
    
  } catch (e) {
    console.error('❌ ECDH computation error:', e);
    throw e;
  }
}

/**
 * Derive session keys từ shared secret
 * (Web Crypto API HKDF đơn giản)
 */
async function deriveSessionKeys(sharedSecretB64, salt) {
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

    // Expand
    const hmacKey2 = await window.crypto.subtle.importKey(
      "raw",
      prk,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const okm = await window.crypto.subtle.sign(
      "HMAC",
      hmacKey2,
      new TextEncoder().encode("E2EE_CHAT_SESSION")
    );

    // Split thành encKey + decKey
    const okmArray = new Uint8Array(okm);
    const encKey = btoa(String.fromCharCode(...okmArray.slice(0, 32)));
    const decKey = btoa(String.fromCharCode(...okmArray.slice(32, 64)));

    return { encKey, decKey };
    
  } catch (e) {
    console.error('❌ Derive keys error:', e);
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

    // Mã hóa
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: new TextEncoder().encode(aad) },
      key,
      new TextEncoder().encode(plaintext)
    );

    return {
      ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
      nonce: btoa(String.fromCharCode(...nonce)),
      tag: btoa(String.fromCharCode(...new Uint8Array(ciphertext).slice(-16))) // GCM tag 
    };
    
  } catch (e) {
    console.error('❌ Encrypt error:', e);
    throw e;
  }
}

/**
 * Giải mã tin nhắn AES-256-GCM
 */
async function decryptMessage(keyB64, ciphertextB64, nonceB64, tagB64, aad) {
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

    // Reconstruct ciphertext với tag
    const cipherArray = Uint8Array.from(atob(ciphertextB64), c => c.charCodeAt(0));
    const tagArray = Uint8Array.from(atob(tagB64), c => c.charCodeAt(0));
    const nonce = Uint8Array.from(atob(nonceB64), c => c.charCodeAt(0));

    const fullCiphertext = new Uint8Array([...cipherArray, ...tagArray]);

    // Giải mã
    const plaintext = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: new TextEncoder().encode(aad) },
      key,
      fullCiphertext
    );

    return new TextDecoder().decode(plaintext);
    
  } catch (e) {
    console.error('❌ Decrypt error:', e);
    throw new Error('Giải mã thất bại: ' + e.message);
  }
}

// ========== INIT ==========
document.getElementById('passwordInput').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') handleLogin();
});

document.getElementById('messageInput').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') handleSendMessage();
});

console.log('🚀 E2EE Chat Client loaded');

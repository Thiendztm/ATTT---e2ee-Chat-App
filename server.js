const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const crypto = require('crypto');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { origin: "*" }
});

// Đơn giản lưu user trong memory (MVP)
const users = new Map(); // userId -> {username, socketId}
const sessions = new Map(); // sessionId -> {userA, userB, status}

app.use(express.static(path.join(__dirname, 'static')));
app.use(express.json());

// ========== ROUTE ==========
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'static', 'index.html'));
});

// ========== SOCKET EVENTS ==========
io.on('connection', (socket) => {
  console.log('🔗 User connected:', socket.id);

  // 1. REGISTER / LOGIN
  socket.on('register', (data) => {
    const { username, password } = data;
    
    if (!username || !password) {
      socket.emit('error', 'Username và password không được trống');
      return;
    }

    // Kiểm tra user đã tồn tại chưa
    const existing = Array.from(users.values()).find(u => u.username === username);
    if (existing) {
      socket.emit('error', 'Username đã tồn tại');
      return;
    }

    // Hash password (đơn giản = SHA256)
    const pwHash = crypto.createHash('sha256').update(password).digest('hex');
    const userId = crypto.randomUUID();

    users.set(userId, {
      username,
      passwordHash: pwHash,
      socketId: socket.id,
      publicKey: null // sẽ gửi sau
    });

    socket.userId = userId;
    socket.emit('registerSuccess', { userId, username });
    console.log(`✅ Register: ${username} (${userId})`);
  });

  socket.on('login', (data) => {
    const { username, password } = data;
    
    const user = Array.from(users.values()).find(u => u.username === username);
    if (!user) {
      socket.emit('error', 'User không tồn tại');
      return;
    }

    const pwHash = crypto.createHash('sha256').update(password).digest('hex');
    if (user.passwordHash !== pwHash) {
      socket.emit('error', 'Mật khẩu sai');
      return;
    }

    socket.userId = Array.from(users.keys()).find(id => users.get(id) === user);
    user.socketId = socket.id; // update socket

    socket.emit('loginSuccess', { userId: socket.userId, username: user.username });
    console.log(`✅ Login: ${username}`);
    
    // Gửi danh sách user online
    broadcastUserList();
  });

  // 2. DANH SACH USER ONLINE
  socket.on('requestUserList', () => {
    if (!socket.userId) {
      socket.emit('error', 'Chưa đăng nhập');
      return;
    }

    const userList = Array.from(users.entries())
      .filter(([id, user]) => id !== socket.userId)
      .map(([id, user]) => ({
        userId: id,
        username: user.username,
        online: true
      }));

    socket.emit('userList', userList);
  });

  // 3. INITIATE KEY EXCHANGE (A yêu cầu trao đổi khóa với B)
  socket.on('initiateKeyExchange', (data) => {
    const { targetUserId, publicKey } = data;
    
    if (!socket.userId) {
      socket.emit('error', 'Chưa đăng nhập');
      return;
    }

    const targetUser = users.get(targetUserId);
    if (!targetUser) {
      socket.emit('error', 'User đích không tồn tại');
      return;
    }

    // Lưu public key của A
    const currentUser = users.get(socket.userId);
    currentUser.publicKey = publicKey;

    // Tạo session ID
    const sessionId = `${socket.userId}-${targetUserId}-${Date.now()}`;
    sessions.set(sessionId, {
      userA: socket.userId,
      userB: targetUserId,
      publicKeyA: publicKey,
      publicKeyB: null,
      status: 'waiting'
    });

    // Gửi yêu cầu tới B
    io.to(targetUser.socketId).emit('keyExchangeRequest', {
      fromUserId: socket.userId,
      fromUsername: currentUser.username,
      publicKey: publicKey,
      sessionId
    });

    console.log(`🔐 Key exchange request: ${currentUser.username} -> ${targetUser.username}`);
  });

  // 4. ACCEPT KEY EXCHANGE (B chấp nhận trao đổi khóa)
  socket.on('acceptKeyExchange', (data) => {
    const { sessionId, publicKey } = data;
    
    const session = sessions.get(sessionId);
    if (!session) {
      socket.emit('error', 'Session không tồn tại');
      return;
    }

    if (session.userB !== socket.userId) {
      socket.emit('error', 'Không có quyền chấp nhận session này');
      return;
    }

    // Lưu public key của B
    const userB = users.get(session.userB);
    userB.publicKey = publicKey;
    session.publicKeyB = publicKey;
    session.status = 'established';

    // Gửi thông báo tới A rằng B đã chấp nhận
    const userA = users.get(session.userA);
    io.to(userA.socketId).emit('keyExchangeAccepted', {
      sessionId,
      fromUserId: session.userB,
      publicKey: publicKey
    });

    console.log(`✅ Key exchange accepted: ${userB.username}`);
  });

  // 5. SEND ENCRYPTED MESSAGE
  socket.on('sendMessage', (data) => {
    const { sessionId, recipientId, ciphertext, nonce, tag, counter } = data;
    
    if (!socket.userId) {
      socket.emit('error', 'Chưa đăng nhập');
      return;
    }

    const session = sessions.get(sessionId);
    if (!session || session.status !== 'established') {
      socket.emit('error', 'Session không hợp lệ hoặc chưa setup');
      return;
    }

    // Relay tin nhắn tới người nhận
    const recipient = users.get(recipientId);
    if (!recipient || !recipient.socketId) {
      socket.emit('error', 'Người nhận offline');
      return;
    }

    io.to(recipient.socketId).emit('receiveMessage', {
      sessionId,
      senderId: socket.userId,
      ciphertext,
      nonce,
      tag,
      counter,
      timestamp: new Date().toISOString()
    });

    console.log(`💬 Message relayed: ${socket.id} -> ${recipient.socketId}`);
  });

  // 6. DISCONNECT
  socket.on('disconnect', () => {
    if (socket.userId) {
      const user = users.get(socket.userId);
      console.log(`❌ Disconnect: ${user?.username || socket.userId}`);
      // Trong MVP không xóa user ngay, để có thể reconnect
      broadcastUserList();
    }
  });
});

// ========== HELPER FUNCTIONS ==========
function broadcastUserList() {
  const userList = Array.from(users.entries()).map(([id, user]) => ({
    userId: id,
    username: user.username,
    online: user.socketId ? true : false
  }));

  io.emit('userListUpdate', userList);
}

// ========== START SERVER ==========
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Server chạy tại http://localhost:${PORT}`);
});

# 🚨 MITM Attack Demo - E2EE Chat Security Test

## Scenario: Bên Thứ 3 Cố Gắng Hack

### **Test Case 1: Hacker Mở Một Tab & Cố Listen**

```
User A (tab 1)      Hacker (tab 3)         User B (tab 2)
   │                    │                      │
   ├── [initiateKeyExchange]                  │
   │       ↓             │                     │
   │ Server relay        │                     │
   │                     ├─ Hacker thấy:      │
   │                     │ {publicKeyA, sessionId}
   │                     │ (nhưng chưa có publicKeyB)
   │                     │
   │                     │  ❌ Hacker không thể tính shared secret
   │                     │     vì thiếu privateKeyB hoặc privateKeyA
   │
   ├─────────────────────────[keyExchangeAccepted]──────B
   │                          │
   │   Hacker thấy: publicKeyB │
   │   Nhưng vẫn không thể tính shared secret!
   │   (vì không có secret của A hoặc B)
```

**Tại sao hacker không thể hack?**
```
Hacker:
  - Thấy: publicKeyA, publicKeyB (công khai)
  - Không có: privateKeyA, privateKeyB (bí mật)
  - Cần: privateKeyA + publicKeyB HOẶC privateKeyB + publicKeyA
  - Tính: ??? (Không thể! ECDH discrete log problem - NP-hard)

→ Hacker không thể tính shared secret → không thể decrypt
```

---

### **Test Case 2: Hacker Gửi Fake Message**

```
Hacker (có tab mở):
  - Nhận thấy {sessionId, ciphertext, nonce}
  - Cố thay đổi ciphertext thành "Transfer all money"
  - Gửi lại

User B nhận (giải mã):
  ❌ AES-GCM authentication tag FAIL
  ❌ "Giải mã thất bại" error
  → Message bị reject!
```

**Tại sao tag fail?**
```javascript
// A mã hóa:
tag = AES-GCM.encrypt(
  key: A.encKey,
  plaintext: "Hello",
  aad: { sessionId, counter: 1 }
);

// Hacker thay đổi:
ciphertext': "Hacked" + original_ciphertext[4:] 
// Vẫn dùng cùng tag cũ

// B giải mã:
plaintext = AES-GCM.decrypt(
  key: B.decKey (= A.encKey),
  ciphertext': "Hacked...", 
  tag: (tag cũ)
);
// ❌ tag không match → OperationError!
```

---

### **Test Case 3: MITM Attack Thực Sự (Hacker Làm Trung Gian)**

```
User A          Hacker (MITM)           User B
   │                  │                    │
   ├─ pubKeyA ──♦── Hacker nhận          │
   │             │   Tạo privateKey_H    │
   │             │   pubKey_H ────→ Relay tới B
   │             │   (giả mạo A)
   │             │
   │             ├── pubKeyB ──♦── Nhận pubKeyB
   │             │   Xác lập 2 sessions:
   │             │   - Session A-H (hacker giả là B)
   │             │   - Session H-B (hacker giả là A)
   │             │
   │             ├──────────────

A ─→ "Hi" ─→ Hacker decrypt (có key A-H)
              ↓ (đọc được tin nhắn!)
              → Hacker re-encrypt (với key H-B) 
              → "Hi" ─→ B

B ←──────────────────────── "Hi"
A ←──────────────────────── "Hi" (B reply)
              ↑ (Hacker re-encrypt lại)
```

**Cách phát hiện MITM:**
```
A thấy fingerprint: F1A2B3C4D5E6F7
B thấy fingerprint: D7C6B5A4F3E2D1

❌ Fingerprint khác nhau!
→ Hacker đang làm trung gian!
```

---

## **Cách Demo MITM Attack Trong App**

### **Step 1: Kiểm Tra Fingerprint Match**

```javascript
// Client A thấy:
✅ E2EE bảo mật thành công
🔑 Fingerprint: F1A2B3C4D5E6F7

// Client B thấy:
✅ E2EE bảo mật thành công
🔑 Fingerprint: F1A2B3C4D5E6F7

✅ Same fingerprint → No MITM!
```

### **Step 2: Mở Tab 3 (Hacker) & Thử Chat**

```
Tab 1: user123 ↔ tab 2: user1234
Tab 3: hacker (login as user999)
```

**Hacker cố listen:**
```javascript
// Browser console của hacker:
> clientState.sessions
> Object {}  // Empty! Hacker chưa có session với user123

// Hacker thấy socket message (ciphertext):
> {sessionId: "123-1234-...", ciphertext: "xyz...", nonce: "abc..."}

// Nhưng decrypt fail:
> decryptMessage(???, ciphertext)  // ❌ Không có key!
> OperationError: Failed to decrypt
```

### **Step 3: Hacker Cố Gắng Forge Message**

```javascript
// Hacker try:
socket.emit('sendMessage', {
  sessionId: "123-1234-...",  // Lấy từ eavesdrop
  ciphertext: "fake_encrypted_content",
  nonce: "fake_nonce"
});

// Server relay, User B nhận
// User B thử decrypt:
❌ AES-GCM tag verification failed
❌ "Giải mã thất bại" 
→ User B biết có gì đó sai!
```

---

## **Tóm Tắt: Tại Sao App Của Bạn An Toàn?**

| Tấn Công | Phòng Vệ | Kết Quả |
|----------|---------|--------|
| **Eavesdrop** | Encryption | ❌ Chỉ thấy ciphertext vô dụng |
| **Forge message** | AES-GCM tag | ❌ Authentication fail |
| **MITM fake key** | Fingerprint verify | ❌ User phát hiện khác key |
| **Replay old message** | Counter | ❌ Counter < lastCounter = reject |
| **Hack server lấy key** | Client-side key | ❌ Server không có key! |

---

## **Bài Tập Cho Bạn**

1. **Mở 3 tabs:** user1, user2, user3
2. **user1 ↔ user2 chat:** → Xem fingerprint
3. **user3 thử eavesdrop:** 
   - Mở DevTools → console
   - Hỏi: `clientState.sessions` → nên là rỗng
   - Thử decrypt message từ user1-user2 → phải fail
4. **user3 thử send fake message:** → Phải bị reject

---

## **Kết Luận Trình Bày Cho Thầy/Cô**

> *"App mình implement E2EE authentication bằng ECDH, mã hóa bằng AES-256-GCM với authentication tag. Ngay cả nếu bên thứ 3 eavesdrop hoặc forge message, họ không thể decrypt do thiếu shared secret, và nếu thay đổi message thì tag validation sẽ fail. Fingerprint verification giúp phát hiện MITM attack khi cả 2 user confirm cùng 1 key fingerprint."*


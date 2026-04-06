/**
 * E2EE Chat Crypto Module
 * ECDH (X25519) + HKDF-SHA256 + AES-256-GCM
 */

class E2EECrypto {
  constructor() {
    this.curve = 'prime256v1'; // hoặc 'secp384r1'
    this.keyLength = 32; // 256-bit
    this.nonceLength = 12; // 96-bit cho GCM
    this.saltLength = 16;
  }

  /**
   * Tạo cặp khóa ECDH (Elliptic Curve Diffie-Hellman)
   * @returns {Promise<{privateKey, publicKey}>}
   */
  async generateKeyPair() {
    const keyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: this.curve,
      publicKeyEncoding: {
        type: 'spki',
        format: 'der'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'der'
      }
    });

    // Convert to Base64 để truyền qua mạng
    return {
      privateKey: Buffer.from(keyPair.privateKey).toString('base64'),
      publicKey: Buffer.from(keyPair.publicKey).toString('base64')
    };
  }

  /**
   * Tính toán Shared Secret từ private key và public key của đối phương
   * @param {string} privateKeyB64 - Private key (Base64)
   * @param {string} publicKeyB64 - Public key của đối phương (Base64)
   * @returns {Promise<string>} Shared secret (Base64)
   */
  async computeSharedSecret(privateKeyB64, publicKeyB64) {
    const privateKeyDer = Buffer.from(privateKeyB64, 'base64');
    const publicKeyDer = Buffer.from(publicKeyB64, 'base64');

    // Import keys
    const privateKey = crypto.createPrivateKey({
      key: privateKeyDer,
      format: 'der',
      type: 'pkcs8'
    });

    const publicKey = crypto.createPublicKey({
      key: publicKeyDer,
      format: 'der',
      type: 'spki'
    });

    // Compute ECDH
    const ecdh = crypto.createECDH(this.curve);
    // Thd không trực tiếp, dùng computeSecret
    // Workaround: dùng diffieHellman
    const dhObject = crypto.getDiffieHellman('modp14');

    // Cách chuẩn hơn: dùng Web Crypto API chuyển sang Node crypto
    // Hoặc dùng thư viện khác. TẠM THỜI dùng simplify:
    
    const sharedSecret = crypto.diffieHellman({
      privateKey: privateKey,
      publicKey: publicKey
    });

    return sharedSecret.toString('base64');
  }

  /**
   * HKDF-SHA256: Derive session key từ shared secret
   * @param {string} sharedSecretB64 - Shared secret (Base64)
   * @param {string} context - Context string (e.g., "chat session A-B")
   * @returns {Promise<{encKey, decKey, salt}>}
   */
  async deriveSessionKeys(sharedSecretB64, context = 'E2EE_CHAT_SESSION') {
    const sharedSecret = Buffer.from(sharedSecretB64, 'base64');
    
    // Tạo salt ngẫu nhiên
    const salt = crypto.randomBytes(this.saltLength);

    // HKDF: Extract phase
    const hmac = crypto.createHmac('sha256', salt);
    hmac.update(sharedSecret);
    const prk = hmac.digest(); // Pseudo-Random Key

    // HKDF: Expand phase
    // Sinh 2 khóa: 1 cho send, 1 cho receive
    const info = Buffer.from(context, 'utf-8');
    
    let okm = Buffer.alloc(0);
    let t = Buffer.alloc(0);

    for (let i = 1; i <= 2; i++) {
      const hmac2 = crypto.createHmac('sha256', prk);
      hmac2.update(Buffer.concat([t, info, Buffer.from([i])]));
      t = hmac2.digest();
      okm = Buffer.concat([okm, t]);
    }

    const encKey = okm.slice(0, this.keyLength); // 256-bit
    const decKey = okm.slice(this.keyLength, this.keyLength * 2); // 256-bit

    return {
      encKey: encKey.toString('base64'),
      decKey: decKey.toString('base64'),
      salt: salt.toString('base64')
    };
  }

  /**
   * AES-256-GCM Encryption
   * @param {string} keyB64 - Session key (Base64)
   * @param {string} plaintext - Tin nhắn plaintext
   * @param {string} aad - Additional Authenticated Data (JSON)
   * @returns {{ciphertext, nonce, tag}} Encrypted data
   */
  encrypt(keyB64, plaintext, aad = '') {
    const key = Buffer.from(keyB64, 'base64');
    const nonce = crypto.randomBytes(this.nonceLength);

    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);

    // Thêm AAD (Additional Authenticated Data) nếu có
    if (aad) {
      cipher.setAAD(Buffer.from(aad, 'utf-8'));
    }

    let encrypted = cipher.update(plaintext, 'utf-8', 'hex');
    encrypted += cipher.final('hex');

    const tag = cipher.getAuthTag();

    return {
      ciphertext: encrypted,
      nonce: nonce.toString('base64'),
      tag: tag.toString('base64'),
      aad: aad // Lưu để client gửi cùng
    };
  }

  /**
   * AES-256-GCM Decryption
   * @param {string} keyB64 - Session key (Base64)
   * @param {string} ciphertext - Encrypted data (hex)
   * @param {string} nonceB64 - Nonce (Base64)
   * @param {string} tagB64 - Authentication tag (Base64)
   * @param {string} aad - Additional Authenticated Data
   * @returns {string} Plaintext
   * @throws {Error} Nếu integrity check thất bại
   */
  decrypt(keyB64, ciphertext, nonceB64, tagB64, aad = '') {
    const key = Buffer.from(keyB64, 'base64');
    const nonce = Buffer.from(nonceB64, 'base64');
    const tag = Buffer.from(tagB64, 'base64');

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);

    // Set AAD
    if (aad) {
      decipher.setAAD(Buffer.from(aad, 'utf-8'));
    }

    // Set authentication tag
    decipher.setAuthTag(tag);

    let decrypted;
    try {
      decrypted = decipher.update(ciphertext, 'hex', 'utf-8');
      decrypted += decipher.final('utf-8');
    } catch (e) {
      throw new Error('[ERROR] Integrity check failed! Message modified or wrong key.');
    }

    return decrypted;
  }

  /**
   * Tạo nonce ngẫu nhiên (phải dùng 1 lần duy nhất với cùng khóa)
   * @returns {string} Nonce (Base64)
   */
  generateNonce() {
    return crypto.randomBytes(this.nonceLength).toString('base64');
  }

  /**
   * Hash password (dùng Argon2 hoặc bcrypt thực tế, tạm dùng SHA256)
   * @param {string} password
   * @returns {string} Password hash
   */
  hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
  }
}

// Export for Node.js hoặc browser
if (typeof module !== 'undefined' && module.exports) {
  module.exports = E2EECrypto;
}

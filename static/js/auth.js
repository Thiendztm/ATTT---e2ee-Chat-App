/**
 * E2EE Chat Auth Logic
 * Login/Register page
 */

const socket = io();

// ========== FUNCTIONS ==========

function handleRegister() {
  const username = document.getElementById('usernameInput').value.trim();
  const password = document.getElementById('passwordInput').value.trim();
  
  console.log('[Register] Attempt:', username);
  
  if (!username || !password) {
    showError('Vui lòng nhập username và password');
    return;
  }

  if (username.length < 3) {
    showError('Username phải ít nhất 3 ký tự');
    return;
  }

  if (password.length < 4) {
    showError('Password phải ít nhất 4 ký tự');
    return;
  }

  console.log('[Register] Send request to server:', username);
  socket.emit('register', { username, password });
}

function handleLogin() {
  const username = document.getElementById('usernameInput').value.trim();
  const password = document.getElementById('passwordInput').value.trim();
  
  console.log('[Login] Attempt:', username);
  
  if (!username || !password) {
    showError('Vui lòng nhập username và password');
    return;
  }

  console.log('[Login] Send request to server:', username);
  socket.emit('login', { username, password });
}

function showError(message) {
  const errorDiv = document.getElementById('authError');
  errorDiv.textContent = message;
  errorDiv.style.display = 'block';
  document.getElementById('successMessage').style.display = 'none';
  
  setTimeout(() => {
    errorDiv.style.display = 'none';
  }, 4000);
}

function showSuccess(message) {
  const successDiv = document.getElementById('successMessage');
  successDiv.textContent = message;
  successDiv.style.display = 'block';
  document.getElementById('authError').style.display = 'none';
  
  setTimeout(() => {
    successDiv.style.display = 'none';
  }, 2000);
}

// ========== SOCKET EVENTS ==========

socket.on('connect', () => {
  console.log('[Connected] Socket:', socket.id);
});

socket.on('registerSuccess', (data) => {
  console.log('[OK] Register:', data);
  showSuccess('Register OK! Please login.');
  
  // Clear fields
  document.getElementById('usernameInput').value = '';
  document.getElementById('passwordInput').value = '';
});

socket.on('loginSuccess', (data) => {
  console.log('[OK] Login:', data);
  showSuccess('Login OK! Redirecting...');
  
  // Lưu user info vào sessionStorage (per tab, không global)
  sessionStorage.setItem('userId', data.userId);
  sessionStorage.setItem('username', data.username);
  
  // Chuyển tới trang chat
  setTimeout(() => {
    window.location.href = '/';
  }, 1500);
});

socket.on('error', (message) => {
  console.error('[ERROR] Server:', message);
  showError(message);
});

socket.on('disconnect', () => {
  console.warn('[WARN] Disconnected');
});

// ========== INIT ==========
document.addEventListener('DOMContentLoaded', () => {
  const usernameInput = document.getElementById('usernameInput');
  const passwordInput = document.getElementById('passwordInput');
  
  if (usernameInput) {
    usernameInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') handleRegister();
    });
  }
  
  if (passwordInput) {
    passwordInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') handleLogin();
    });
  }
});

console.log('[Auth] Page loaded');

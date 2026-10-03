// Frontend client logic for Task 02 Demonstration

const regForm = document.getElementById('register-form');
const loginForm = document.getElementById('login-form');
const regAlert = document.getElementById('register-alert');
const loginAlert = document.getElementById('login-alert');
const dashboardAlert = document.getElementById('dashboard-alert');
const btnLogout = document.getElementById('btn-logout');
const btnRefreshProfile = document.getElementById('btn-refresh-profile');
const btnCheckProtected = document.getElementById('btn-check-protected');
const btnSimulateFail = document.getElementById('btn-simulate-fail');

const authDot = document.getElementById('auth-dot');
const authStatusText = document.getElementById('auth-status-text');
const unauthView = document.getElementById('unauthenticated-view');
const authView = document.getElementById('authenticated-view');
const userDisplay = document.getElementById('user-display');
const userIdDisplay = document.getElementById('user-id-display');
const userCreatedDisplay = document.getElementById('user-created-display');

function showAlert(element, message, type = 'error') {
  element.textContent = message;
  element.className = `alert ${type}`;
  element.classList.remove('hidden');
}

function hideAlert(element) {
  element.classList.add('hidden');
}

// Check session state on page load
async function checkSession() {
  try {
    const res = await fetch('/api/session-status');
    const data = await res.json();
    if (data.authenticated) {
      setAuthenticatedUI(data.user);
      loadProfileData();
    } else {
      setUnauthenticatedUI();
    }
  } catch (err) {
    setUnauthenticatedUI();
  }
}

function setAuthenticatedUI(user) {
  authDot.classList.add('active');
  authStatusText.textContent = `Active Session: ${user.username}`;
  unauthView.classList.add('hidden');
  authView.classList.remove('hidden');
  userDisplay.textContent = user.username;
  userIdDisplay.textContent = user.id;
}

function setUnauthenticatedUI() {
  authDot.classList.remove('active');
  authStatusText.textContent = 'Unauthenticated (No Session)';
  unauthView.classList.remove('hidden');
  authView.classList.add('hidden');
}

async function loadProfileData() {
  try {
    const res = await fetch('/api/profile');
    const data = await res.json();
    if (res.ok) {
      userDisplay.textContent = data.user.username;
      userIdDisplay.textContent = data.user.id;
      userCreatedDisplay.textContent = new Date(data.user.createdAt).toLocaleString();
      hideAlert(dashboardAlert);
    } else {
      showAlert(dashboardAlert, data.error || 'Session expired. Please log in again.', 'error');
      setUnauthenticatedUI();
    }
  } catch (err) {
    showAlert(dashboardAlert, 'Network error reaching /api/profile', 'error');
  }
}

// Register Form Submit
regForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert(regAlert);

  const username = document.getElementById('reg-username').value;
  const password = document.getElementById('reg-password').value;

  try {
    const res = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();

    if (res.ok) {
      showAlert(regAlert, `✅ ${data.message} User: ${data.user.username}`, 'success');
      document.getElementById('login-username').value = username;
      document.getElementById('login-password').value = password;
      regForm.reset();
    } else {
      showAlert(regAlert, `❌ Registration Rejected: ${data.error}`, 'error');
    }
  } catch (err) {
    showAlert(regAlert, 'Failed to connect to registration endpoint.', 'error');
  }
});

// Login Form Submit
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  hideAlert(loginAlert);

  const username = document.getElementById('login-username').value;
  const password = document.getElementById('login-password').value;

  await performLogin(username, password);
});

// Simulate failed login button (demonstrating rate limiting and generic error)
btnSimulateFail.addEventListener('click', async () => {
  const username = document.getElementById('login-username').value || 'random_target';
  const wrongPassword = 'IncorrectPassword123!';
  await performLogin(username, wrongPassword);
});

async function performLogin(username, password) {
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const data = await res.json();

    if (res.status === 200) {
      showAlert(loginAlert, `✅ Login Successful! Session created for ${data.user.username}`, 'success');
      setAuthenticatedUI(data.user);
      loadProfileData();
    } else if (res.status === 429) {
      showAlert(loginAlert, `⚠️ Rate Limit Triggered (HTTP 429): ${data.error}`, 'warning');
    } else if (res.status === 401) {
      showAlert(loginAlert, `❌ Generic Auth Error (HTTP 401): ${data.error}`, 'error');
    } else {
      showAlert(loginAlert, `❌ Error (${res.status}): ${data.error || 'Login failed.'}`, 'error');
    }
  } catch (err) {
    showAlert(loginAlert, 'Failed to connect to login endpoint.', 'error');
  }
}

// Logout
btnLogout.addEventListener('click', async () => {
  try {
    const res = await fetch('/api/logout', { method: 'POST' });
    const data = await res.json();
    showAlert(dashboardAlert, `👋 ${data.message}`, 'success');
    setUnauthenticatedUI();
  } catch (err) {
    showAlert(dashboardAlert, 'Failed to log out.', 'error');
  }
});

// Refresh / test profile button
btnRefreshProfile.addEventListener('click', loadProfileData);
btnCheckProtected.addEventListener('click', async () => {
  try {
    const res = await fetch('/api/profile');
    const data = await res.json();
    if (res.ok) {
      showAlert(dashboardAlert, `Access Granted: Logged in as ${data.user.username}`, 'success');
    } else {
      showAlert(dashboardAlert, `⛔ HTTP ${res.status}: ${data.error}`, 'error');
    }
  } catch (err) {
    showAlert(dashboardAlert, 'Error checking protected route.', 'error');
  }
});

// Initialize on page load
checkSession();

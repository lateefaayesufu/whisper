// ─── WhisperBox API Layer ──────────────────────────────────────────────────

const API = (() => {
  const BASE = 'https://whisperbox.koyeb.app';

  // ── Token store (in-memory only) ─────────────────────────────────────────
  let _accessToken = null;
  let _refreshToken = null;
  let _refreshTimer = null;

  function setTokens(access, refresh, expiresIn = 900) {
    _accessToken = access;
    if (refresh) _refreshToken = refresh;
    // Proactively refresh 60s before expiry
    clearTimeout(_refreshTimer);
    _refreshTimer = setTimeout(refreshTokens, (expiresIn - 60) * 1000);
  }

  function clearTokens() {
    _accessToken = null;
    _refreshToken = null;
    clearTimeout(_refreshTimer);
  }

  function getAccessToken() { return _accessToken; }
  function getRefreshToken() { return _refreshToken; }

  // ── Core fetch wrapper ───────────────────────────────────────────────────
  async function request(path, options = {}, retry = true) {
    const headers = { 'Content-Type': 'application/json', ...options.headers };
    if (_accessToken) headers['Authorization'] = `Bearer ${_accessToken}`;

    const res = await fetch(`${BASE}${path}`, {
      ...options,
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });

    // Auto-refresh on 401 if we have a refresh token
    if (res.status === 401 && retry && _refreshToken) {
      const refreshed = await refreshTokens();
      if (refreshed) return request(path, options, false);
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw Object.assign(new Error(err.detail || 'Request failed'), { status: res.status, data: err });
    }

    if (res.status === 204) return null;
    return res.json();
  }

  // ── Auth ─────────────────────────────────────────────────────────────────
  async function register({ username, display_name, password, public_key, wrapped_private_key, pbkdf2_salt }) {
    const data = await request('/auth/register', {
      method: 'POST',
      body: { username, display_name, password, public_key, wrapped_private_key, pbkdf2_salt },
    });
    setTokens(data.access_token, data.refresh_token, data.expires_in);
    return data;
  }

  async function login({ username, password }) {
    const data = await request('/auth/login', {
      method: 'POST',
      body: { username, password },
    });
    setTokens(data.access_token, data.refresh_token, data.expires_in);
    return data;
  }

  async function getMe() {
    return request('/auth/me');
  }

  async function refreshTokens() {
    if (!_refreshToken) return false;
    try {
      const data = await request('/auth/refresh', {
        method: 'POST',
        body: { refresh_token: _refreshToken },
      }, false);
      setTokens(data.access_token, null, data.expires_in);
      return true;
    } catch {
      clearTokens();
      return false;
    }
  }

  async function logout() {
    try {
      await request('/auth/logout', {
        method: 'POST',
        body: { refresh_token: _refreshToken },
      });
    } finally {
      clearTokens();
    }
  }

  // ── Users ─────────────────────────────────────────────────────────────────
  async function searchUsers(q) {
    return request(`/users/search?q=${encodeURIComponent(q)}`);
  }

  async function getUserPublicKey(userId) {
    const data = await request(`/users/${userId}/public-key`);
    return data.public_key;
  }

  // ── Conversations ─────────────────────────────────────────────────────────
  async function getConversations() {
    return request('/conversations');
  }

  async function getMessages(userId, { limit = 50, before } = {}) {
    let path = `/conversations/${userId}/messages?limit=${limit}`;
    if (before) path += `&before=${encodeURIComponent(before)}`;
    return request(path);
  }

  // ── Send message (HTTP fallback) ──────────────────────────────────────────
  async function sendMessage(to, payload) {
    return request('/messages', {
      method: 'POST',
      body: { to, payload },
    });
  }

  return {
    setTokens,
    clearTokens,
    getAccessToken,
    getRefreshToken,
    register,
    login,
    getMe,
    refreshTokens,
    logout,
    searchUsers,
    getUserPublicKey,
    getConversations,
    getMessages,
    sendMessage,
  };
})();

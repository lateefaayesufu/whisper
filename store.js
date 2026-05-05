// ─── WhisperBox App State ─────────────────────────────────────────────────
// Session stored in sessionStorage (clears on tab close)
// Private key NEVER persisted — only in memory

const Store = (() => {
  // In-memory only (never persisted)
  let _privateKey = null;

  // Session storage keys
  const SK = {
    USER: 'wb_user',
    REFRESH: 'wb_refresh',
  };

  // ── Session persistence (survives page reload within tab) ─────────────────
  function saveSession(user, refreshToken) {
    sessionStorage.setItem(SK.USER, JSON.stringify(user));
    sessionStorage.setItem(SK.REFRESH, refreshToken);
  }

  function loadSession() {
    try {
      const user = JSON.parse(sessionStorage.getItem(SK.USER));
      const refreshToken = sessionStorage.getItem(SK.REFRESH);
      return user && refreshToken ? { user, refreshToken } : null;
    } catch {
      return null;
    }
  }

  function clearSession() {
    sessionStorage.removeItem(SK.USER);
    sessionStorage.removeItem(SK.REFRESH);
    _privateKey = null;
  }

  // ── Private key (memory only) ─────────────────────────────────────────────
  function setPrivateKey(key) { _privateKey = key; }
  function getPrivateKey() { return _privateKey; }

  // ── Current user ─────────────────────────────────────────────────────────
  let _currentUser = null;
  function setCurrentUser(u) { _currentUser = u; }
  function getCurrentUser() { return _currentUser; }

  // ── Active conversation ───────────────────────────────────────────────────
  let _activeConvUser = null;
  function setActiveConv(user) { _activeConvUser = user; }
  function getActiveConv() { return _activeConvUser; }

  // ── Public key cache ──────────────────────────────────────────────────────
  const _pubKeyCache = new Map();
  function cachePubKey(userId, b64) { _pubKeyCache.set(userId, b64); }
  function getCachedPubKey(userId) { return _pubKeyCache.get(userId); }

  // ── Online presence ───────────────────────────────────────────────────────
  const _online = new Set();
  function setOnline(userId) { _online.add(userId); }
  function setOffline(userId) { _online.delete(userId); }
  function isOnline(userId) { return _online.has(userId); }

  return {
    saveSession, loadSession, clearSession,
    setPrivateKey, getPrivateKey,
    setCurrentUser, getCurrentUser,
    setActiveConv, getActiveConv,
    cachePubKey, getCachedPubKey,
    setOnline, setOffline, isOnline,
  };
})();

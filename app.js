// ─── WhisperBox App ────────────────────────────────────────────────────────

const App = (() => {
  // ── DOM refs ─────────────────────────────────────────────────────────────
  const $ = (id) => document.getElementById(id);
  const $$ = (sel) => document.querySelectorAll(sel);

  // ── Init ─────────────────────────────────────────────────────────────────
  async function init() {
    setupAuthUI();
    setupAppUI();

    // Try to restore session (e.g. page refresh within tab)
    const session = Store.loadSession();
    if (session) {
      try {
        API.setTokens(null, session.refreshToken);
        const ok = await API.refreshTokens();
        if (ok) {
          Store.setCurrentUser(session.user);
          // Re-derive private key — we can't get it back without the password
          // so we prompt the user to re-enter it
          showScreen("app");
          showReauthModal(session.user);
          return;
        }
      } catch {}
    }

    showScreen("auth");
  }

  // ── Screen switching ──────────────────────────────────────────────────────
  function showScreen(name) {
    $("auth-screen").style.display = name === "auth" ? "flex" : "none";
    $("app-screen").style.display = name === "app" ? "flex" : "none";
  }

  // ── Auth UI ───────────────────────────────────────────────────────────────
  function setupAuthUI() {
    // Tab switching
    $$(".auth-tab").forEach((tab) => {
      tab.addEventListener("click", () => {
        $$(".auth-tab").forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");
        $$(".auth-form").forEach((f) => f.classList.remove("active"));
        $(`${tab.dataset.tab}-form`).classList.add("active");
        clearAuthError();
      });
    });

    // Register
    $("register-btn").addEventListener("click", handleRegister);
    $("register-form").addEventListener("keydown", (e) => {
      if (e.key === "Enter") handleRegister();
    });

    // Login
    $("login-btn").addEventListener("click", handleLogin);
    $("login-form").addEventListener("keydown", (e) => {
      if (e.key === "Enter") handleLogin();
    });
  }

  async function handleRegister() {
    const username = $("reg-username").value.trim();
    const displayName = $("reg-display").value.trim();
    const password = $("reg-password").value;
    const confirm = $("reg-confirm").value;

    if (!username || !displayName || !password)
      return showAuthError("All fields are required.", "register");
    if (password !== confirm)
      return showAuthError("Passwords do not match.", "register");
    if (password.length < 8)
      return showAuthError(
        "Password must be at least 8 characters.",
        "register",
      );

    setAuthLoading(true, "Generating encryption keys…", "register");
    try {
      // 1. Generate RSA keypair
      const keyPair = await Crypto.generateRSAKeyPair();
      const publicKeyB64 = await Crypto.exportPublicKey(keyPair.publicKey);

      // 2. Wrap private key with password
      setAuthLoading(true, "Encrypting private key…", "register");
      const { wrappedPrivateKey, pbkdf2Salt } = await Crypto.wrapPrivateKey(
        keyPair.privateKey,
        password,
      );

      // 3. Register
      setAuthLoading(true, "Creating account…", "register");
      const data = await API.register({
        username,
        display_name: displayName,
        password,
        public_key: publicKeyB64,
        wrapped_private_key: wrappedPrivateKey,
        pbkdf2_salt: pbkdf2Salt,
      });

      // 4. Store private key in memory
      Store.setPrivateKey(keyPair.privateKey);
      Store.setCurrentUser(data.user);
      Store.cachePubKey(data.user.id, publicKeyB64);
      Store.saveSession(data.user, data.refresh_token);

      await enterApp();
    } catch (err) {
      showAuthError(err.message || "Registration failed.", "register");
    } finally {
      setAuthLoading(false, "", "register");
    }
  }

  async function handleLogin() {
    const username = $("login-username").value.trim();
    const password = $("login-password").value;

    if (!username || !password)
      return showAuthError("Username and password required.", "login");

    setAuthLoading(true, "Signing in…", "login");
    try {
      const data = await API.login({ username, password });

      setAuthLoading(true, "Decrypting private key…", "login");
      const privateKey = await Crypto.unwrapPrivateKey(
        data.user.wrapped_private_key,
        data.user.pbkdf2_salt,
        password,
      );

      Store.setPrivateKey(privateKey);
      Store.setCurrentUser(data.user);
      Store.cachePubKey(data.user.id, data.user.public_key);
      Store.saveSession(data.user, data.refresh_token);

      await enterApp();
    } catch (err) {
      if (err.status === 401) {
        showAuthError("Invalid username or password.", "login");
      } else if (err.message && err.message.includes("unwrap")) {
        showAuthError("Failed to decrypt keys — wrong password?", "login");
      } else {
        showAuthError(err.message || "Login failed.", "login");
      }
    } finally {
      setAuthLoading(false, "", "login");
    }
  }

  // activeForm tracks which form is currently visible
  function activeFormPrefix() {
    return $("login-form").classList.contains("active") ? "login" : "register";
  }

  function showAuthError(msg, form) {
    const prefix = form || activeFormPrefix();
    const el = $(`${prefix}-error`);
    if (!el) return;
    el.textContent = msg;
    el.style.display = "block";
  }

  function clearAuthError() {
    ["login-error", "register-error"].forEach((id) => {
      const el = $(id);
      if (el) {
        el.textContent = "";
        el.style.display = "none";
      }
    });
  }

  function setAuthLoading(on, label = "Loading…", form) {
    $("register-btn").disabled = on;
    $("login-btn").disabled = on;
    const prefix = form || activeFormPrefix();
    const loadEl = $(`${prefix}-loading`);
    if (loadEl) {
      loadEl.textContent = on ? label : "";
      loadEl.style.display = on ? "block" : "none";
    }
  }

  // ── Re-auth modal (session restore needs password for private key) ─────────
  function showReauthModal(user) {
    const modal = $("reauth-modal");
    modal.style.display = "flex";
    $("reauth-name").textContent = user.display_name || user.username;

    $("reauth-btn").onclick = async () => {
      const password = $("reauth-password").value;
      if (!password) return;
      $("reauth-error").style.display = "none";
      $("reauth-btn").disabled = true;
      $("reauth-btn").textContent = "Decrypting…";
      try {
        const privateKey = await Crypto.unwrapPrivateKey(
          user.wrapped_private_key,
          user.pbkdf2_salt,
          password,
        );
        Store.setPrivateKey(privateKey);
        Store.cachePubKey(user.id, user.public_key);
        modal.style.display = "none";
        await enterApp();
      } catch {
        $("reauth-error").textContent = "Wrong password.";
        $("reauth-error").style.display = "block";
        $("reauth-btn").disabled = false;
        $("reauth-btn").textContent = "Unlock";
      }
    };

    $("reauth-password").addEventListener("keydown", (e) => {
      if (e.key === "Enter") $("reauth-btn").click();
    });

    $("reauth-logout").onclick = () => {
      modal.style.display = "none";
      doLogout();
    };
  }

  // ── Enter app after successful auth ──────────────────────────────────────
  async function enterApp() {
    showScreen("app");
    renderCurrentUser();
    await loadConversations();
    connectWebSocket();
    // Show empty state initially
    showEmptyState();
  }

  function renderCurrentUser() {
    const user = Store.getCurrentUser();
    if (!user) return;
    $("current-username").textContent = "@" + user.username;
  }

  // ── App UI ────────────────────────────────────────────────────────────────
  // ── Mobile helpers ────────────────────────────────────────────────────────
  function isMobile() {
    return window.innerWidth <= 640;
  }

  function openMobileChat() {
    if (!isMobile()) return;
    $("sidebar").classList.add("chat-open");
  }

  function closeMobileChat() {
    if (!isMobile()) return;
    $("sidebar").classList.remove("chat-open");
  }

  function setupAppUI() {
    // Logout
    $("logout-btn").addEventListener("click", doLogout);

    // New chat button
    $("new-chat-btn").addEventListener("click", () => {
      toggleSearchPanel(true);
    });

    // Back button (mobile only — goes back to sidebar/conv list)
    const backBtn = $("back-btn");
    if (backBtn) {
      backBtn.addEventListener("click", () => {
        closeMobileChat();
        showEmptyState();
        // Deselect active conv item
        $$(".conv-item").forEach((el) => el.classList.remove("active"));
        Store.setActiveConv(null);
      });
    }

    // User search
    let searchTimer;
    $("user-search-input").addEventListener("input", (e) => {
      clearTimeout(searchTimer);
      const q = e.target.value.trim();
      if (q.length < 2) {
        $("search-results").innerHTML = "";
        return;
      }
      searchTimer = setTimeout(() => performUserSearch(q), 300);
    });

    $("search-close-btn").addEventListener("click", () => {
      toggleSearchPanel(false);
      $("user-search-input").value = "";
      $("search-results").innerHTML = "";
    });

    // Message input
    $("msg-input").addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        handleSendMessage();
      }
    });

    $("send-btn").addEventListener("click", handleSendMessage);

    // Auto-resize textarea
    $("msg-input").addEventListener("input", function () {
      this.style.height = "auto";
      this.style.height = Math.min(this.scrollHeight, 160) + "px";
    });
  }

  function toggleSearchPanel(show) {
    $("search-panel").style.display = show ? "flex" : "none";
    if (show) $("user-search-input").focus();
  }

  // ── Conversations ─────────────────────────────────────────────────────────
  async function loadConversations() {
    try {
      const convs = await API.getConversations();
      renderConversationList(convs);
    } catch (err) {
      console.error("Failed to load conversations:", err);
    }
  }

  function renderConversationList(convs) {
    const list = $("conv-list");
    if (!convs || convs.length === 0) {
      list.innerHTML =
        '<div class="conv-empty">No conversations yet.<br>Start a new chat.</div>';
      return;
    }
    list.innerHTML = convs
      .map(
        (c) => `
      <div class="conv-item" data-userid="${c.user_id}" data-username="${c.username}" data-displayname="${c.display_name}">
        <div class="conv-avatar">${getInitials(c.display_name || c.username)}</div>
        <div class="conv-info">
          <div class="conv-name">${escHtml(c.display_name || c.username)}</div>
          <div class="conv-meta">@${escHtml(c.username)}</div>
        </div>
        <div class="conv-presence" id="presence-${c.user_id}"></div>
      </div>
    `,
      )
      .join("");

    list.querySelectorAll(".conv-item").forEach((item) => {
      item.addEventListener("click", () =>
        openConversation({
          id: item.dataset.userid,
          username: item.dataset.username,
          display_name: item.dataset.displayname,
        }),
      );
    });
  }

  // ── User Search ───────────────────────────────────────────────────────────
  async function performUserSearch(q) {
    const results = $("search-results");
    results.innerHTML = '<div class="search-loading">Searching…</div>';
    try {
      const users = await API.searchUsers(q);
      if (!users || users.length === 0) {
        results.innerHTML = '<div class="search-empty">No users found.</div>';
        return;
      }
      results.innerHTML = users
        .map(
          (u) => `
        <div class="search-result-item" data-userid="${u.id}" data-username="${u.username}" data-displayname="${u.display_name}">
          <div class="conv-avatar small">${getInitials(u.display_name || u.username)}</div>
          <div>
            <div class="conv-name">${escHtml(u.display_name || u.username)}</div>
            <div class="conv-meta">@${escHtml(u.username)}</div>
          </div>
        </div>
      `,
        )
        .join("");

      results.querySelectorAll(".search-result-item").forEach((item) => {
        item.addEventListener("click", () => {
          toggleSearchPanel(false);
          $("user-search-input").value = "";
          $("search-results").innerHTML = "";
          openConversation({
            id: item.dataset.userid,
            username: item.dataset.username,
            display_name: item.dataset.displayname,
          });
        });
      });
    } catch {
      results.innerHTML =
        '<div class="search-empty">Search failed. Try again.</div>';
    }
  }

  // ── Open Conversation ─────────────────────────────────────────────────────
  async function openConversation(user) {
    Store.setActiveConv(user);

    // On mobile: slide sidebar away, reveal chat
    openMobileChat();

    // Highlight active in sidebar
    $$(".conv-item").forEach((el) => el.classList.remove("active"));
    const convItem = document.querySelector(
      `.conv-item[data-userid="${user.id}"]`,
    );
    if (convItem) convItem.classList.add("active");

    // Update header
    $("chat-header").style.display = "flex";
    $("chat-name").textContent = user.display_name || user.username;
    $("chat-username").textContent = "@" + user.username;
    $("chat-avatar").textContent = getInitials(
      user.display_name || user.username,
    );
    updateOnlineIndicator(user.id);

    // Show message area
    $("empty-state").style.display = "none";
    $("chat-area").style.display = "flex";

    // Clear messages and load history
    $("messages-container").innerHTML = "";
    $("msg-input").value = "";
    $("msg-input").style.height = "auto";
    $("msg-input").disabled = false;
    $("send-btn").disabled = false;

    // Cache their public key
    try {
      if (!Store.getCachedPubKey(user.id)) {
        const pubKey = await API.getUserPublicKey(user.id);
        Store.cachePubKey(user.id, pubKey);
      }
    } catch (err) {
      console.error("Failed to fetch public key:", err);
    }

    await loadMessageHistory(user.id);
    $("msg-input").focus();
  }

  // ── Message History ───────────────────────────────────────────────────────
  async function loadMessageHistory(userId) {
    const container = $("messages-container");
    container.innerHTML = '<div class="msg-loading">Decrypting messages…</div>';

    try {
      const messages = await API.getMessages(userId, { limit: 50 });
      container.innerHTML = "";

      if (!messages || messages.length === 0) {
        container.innerHTML =
          '<div class="msg-empty">No messages yet. Say hello!</div>';
        return;
      }

      // API returns newest first — reverse to show oldest first
      const sorted = [...messages].reverse();
      for (const msg of sorted) {
        await appendMessage(msg, false);
      }

      scrollToBottom();
    } catch (err) {
      container.innerHTML = `<div class="msg-error">Failed to load messages: ${escHtml(err.message)}</div>`;
    }
  }

  // ── Render a message ──────────────────────────────────────────────────────
  async function appendMessage(msg, scroll = true) {
    const me = Store.getCurrentUser();
    const isSender = msg.from_user_id === me.id;
    const privateKey = Store.getPrivateKey();
    const container = $("messages-container");

    const wrapper = document.createElement("div");
    wrapper.classList.add("msg-wrapper", isSender ? "sent" : "received");
    wrapper.dataset.msgid = msg.id;

    const bubble = document.createElement("div");
    bubble.classList.add("msg-bubble");
    bubble.textContent = "Decrypting…";
    wrapper.appendChild(bubble);

    const ts = document.createElement("div");
    ts.classList.add("msg-ts");
    ts.textContent = formatTime(msg.created_at);
    wrapper.appendChild(ts);

    // Remove "no messages" placeholder if present
    const empty = container.querySelector(".msg-empty");
    if (empty) empty.remove();

    container.appendChild(wrapper);
    if (scroll) scrollToBottom();

    // Decrypt async
    try {
      const plaintext = await Crypto.decryptPayload(
        msg.payload,
        privateKey,
        isSender,
      );
      bubble.textContent = plaintext;
      bubble.classList.add("decrypted");
    } catch {
      bubble.textContent = "[Failed to decrypt]";
      bubble.classList.add("decrypt-error");
    }
  }

  // ── Send Message ──────────────────────────────────────────────────────────
  async function handleSendMessage() {
    const input = $("msg-input");
    const text = input.value.trim();
    if (!text) return;

    const conv = Store.getActiveConv();
    if (!conv) return;

    const me = Store.getCurrentUser();
    const recipientPubKey = Store.getCachedPubKey(conv.id);
    const selfPubKey = Store.getCachedPubKey(me.id) || me.public_key;

    if (!recipientPubKey) {
      showToast("Cannot encrypt: missing recipient key.", "error");
      return;
    }

    input.value = "";
    input.style.height = "auto";
    $("send-btn").disabled = true;

    try {
      const payload = await Crypto.encryptForRecipient(
        text,
        recipientPubKey,
        selfPubKey,
      );

      // Optimistic UI — fake msg object so we can render immediately
      const optimisticMsg = {
        id: `optimistic-${Date.now()}`,
        from_user_id: me.id,
        to_user_id: conv.id,
        payload,
        created_at: new Date().toISOString(),
      };

      // Try WebSocket first, fallback to HTTP
      const sent = WS.sendMessage(conv.id, payload);
      if (!sent) {
        await API.sendMessage(conv.id, payload);
      }

      await appendMessage(optimisticMsg, true);

      // Refresh conversation list to update ordering
      loadConversations();
    } catch (err) {
      showToast("Send failed: " + (err.message || "Unknown error"), "error");
      input.value = text; // restore
    } finally {
      $("send-btn").disabled = false;
      input.focus();
    }
  }

  // ── WebSocket ─────────────────────────────────────────────────────────────
  function connectWebSocket() {
    WS.on("connected", () => {
      const el = $("ws-status");
      el.className = "ws-status online";
      // Preserve the dot span, just ensure it exists
      if (!el.querySelector(".ws-dot")) {
        el.innerHTML = '<span class="ws-dot"></span>';
      }
    });

    WS.on("disconnected", () => {
      const el = $("ws-status");
      el.className = "ws-status offline";
      if (!el.querySelector(".ws-dot")) {
        el.innerHTML = '<span class="ws-dot"></span>';
      }
    });

    WS.on("auth-failed", () => {
      doLogout();
    });

    WS.on("message.receive", async (msg) => {
      const conv = Store.getActiveConv();
      // If this message belongs to the active conversation, append it
      if (
        conv &&
        (msg.from_user_id === conv.id || msg.to_user_id === conv.id)
      ) {
        await appendMessage(msg, true);
      }
      // Refresh conversation list for ordering/new conv
      loadConversations();
      // Show notification if not active conv
      if (!conv || msg.from_user_id !== conv.id) {
        // Try to find display name from conversation list
        const convItem = document.querySelector(
          `.conv-item[data-userid="${msg.from_user_id}"]`,
        );
        const senderName = convItem
          ? convItem.dataset.displayname || convItem.dataset.username
          : "Someone";
        showToast(`New message from ${senderName}`, "info");
      }
    });

    WS.on("user.online", ({ user_id }) => {
      Store.setOnline(user_id);
      updateOnlineIndicator(user_id);
      const dot = document.getElementById(`presence-${user_id}`);
      if (dot) {
        dot.className = "conv-presence online";
        dot.title = "Online";
      }
    });

    WS.on("user.offline", ({ user_id }) => {
      Store.setOffline(user_id);
      updateOnlineIndicator(user_id);
      const dot = document.getElementById(`presence-${user_id}`);
      if (dot) {
        dot.className = "conv-presence";
        dot.title = "";
      }
    });

    WS.connect();
  }

  function updateOnlineIndicator(userId) {
    const indicator = $("chat-online");
    if (!indicator) return;
    const conv = Store.getActiveConv();
    if (conv && conv.id === userId) {
      indicator.textContent = Store.isOnline(userId) ? "● Online" : "";
      indicator.style.display = Store.isOnline(userId) ? "block" : "none";
    }
  }

  // ── Logout ────────────────────────────────────────────────────────────────
  async function doLogout() {
    WS.disconnect();
    try {
      await API.logout();
    } catch {}
    Store.clearSession();
    API.clearTokens();
    showScreen("auth");
    $("conv-list").innerHTML = "";
    $("messages-container").innerHTML = "";
    showEmptyState();
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  function showEmptyState() {
    $("empty-state").style.display = "flex";
    $("chat-area").style.display = "none";
    $("chat-header").style.display = "none";
    // On mobile: always return to sidebar when no conv is open
    closeMobileChat();
  }

  function scrollToBottom() {
    const c = $("messages-container");
    c.scrollTop = c.scrollHeight;
  }

  function getInitials(name) {
    if (!name) return "?";
    return name
      .split(" ")
      .map((w) => w[0])
      .join("")
      .slice(0, 2)
      .toUpperCase();
  }

  function escHtml(str) {
    const d = document.createElement("div");
    d.textContent = str;
    return d.innerHTML;
  }

  function formatTime(iso) {
    const d = new Date(iso);
    const now = new Date();
    const isToday = d.toDateString() === now.toDateString();
    if (isToday)
      return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    return (
      d.toLocaleDateString([], { month: "short", day: "numeric" }) +
      " " +
      d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    );
  }

  // ── Toast notifications ───────────────────────────────────────────────────
  function showToast(msg, type = "info") {
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.textContent = msg;
    $("toast-container").appendChild(toast);
    setTimeout(() => toast.classList.add("visible"), 10);
    setTimeout(() => {
      toast.classList.remove("visible");
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }

  return { init };
})();

document.addEventListener("DOMContentLoaded", App.init);

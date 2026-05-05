// ─── WhisperBox WebSocket Manager ─────────────────────────────────────────

const WS = (() => {
  const BASE_WS = 'wss://whisperbox.koyeb.app/ws';

  let _socket = null;
  let _handlers = {};
  let _reconnectTimer = null;
  let _intentionalClose = false;

  function on(event, handler) {
    _handlers[event] = handler;
  }

  function emit(event, data) {
    if (_handlers[event]) _handlers[event](data);
  }

  function connect() {
    const token = API.getAccessToken();
    if (!token) return;

    _intentionalClose = false;
    _socket = new WebSocket(`${BASE_WS}?token=${token}`);

    _socket.onopen = () => {
      console.log('[WS] Connected');
      emit('connected', {});
    };

    _socket.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        emit(msg.event, msg);
      } catch {
        console.warn('[WS] Bad message:', e.data);
      }
    };

    _socket.onclose = async (e) => {
      console.log('[WS] Closed:', e.code, e.reason);
      emit('disconnected', { code: e.code });

      if (_intentionalClose) return;

      if (e.code === 4001) {
        // Token expired → refresh then reconnect
        const ok = await API.refreshTokens();
        if (ok) {
          _reconnectTimer = setTimeout(connect, 500);
        } else {
          emit('auth-failed', {});
        }
      } else if (e.code === 4003) {
        // Invalid token → force login
        emit('auth-failed', {});
      } else {
        // Network error → reconnect with backoff
        _reconnectTimer = setTimeout(connect, 3000);
      }
    };

    _socket.onerror = (e) => {
      console.warn('[WS] Error:', e);
    };
  }

  function disconnect() {
    _intentionalClose = true;
    clearTimeout(_reconnectTimer);
    if (_socket) {
      _socket.close();
      _socket = null;
    }
  }

  function send(data) {
    if (_socket && _socket.readyState === WebSocket.OPEN) {
      _socket.send(JSON.stringify(data));
      return true;
    }
    return false;
  }

  function sendMessage(toUserId, payload) {
    return send({ event: 'message.send', to: toUserId, payload });
  }

  function isConnected() {
    return _socket && _socket.readyState === WebSocket.OPEN;
  }

  return { on, connect, disconnect, sendMessage, isConnected };
})();

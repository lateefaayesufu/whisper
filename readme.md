# WhisperBox

A browser-based, end-to-end encrypted messaging application. The server stores and routes encrypted blobs only — plaintext never leaves the client device.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Architecture Diagram](#architecture-diagram)
3. [Encryption Flow](#encryption-flow)
4. [Key Management](#key-management)
5. [Security Trade-offs](#security-trade-offs)
6. [Known Limitations](#known-limitations)
7. [Running Locally](#running-locally)
8. [API Reference](#api-reference)

---

## Architecture Overview

WhisperBox is split into two clear layers with a strict boundary: the server handles identity, routing, and persistence of opaque blobs; the client handles all cryptographic operations.

### Frontend (this repository)

| File         | Responsibility                                                               |
| ------------ | ---------------------------------------------------------------------------- |
| `index.html` | Application shell, auth screen, chat UI                                      |
| `crypto.js`  | All key generation, encryption, and decryption via Web Crypto API            |
| `api.js`     | HTTP client — wraps every API call, manages JWT tokens in memory             |
| `ws.js`      | WebSocket connection manager — real-time delivery, auto-reconnect            |
| `store.js`   | Runtime state — private key held in memory only, session in `sessionStorage` |
| `app.js`     | Application logic — auth flows, conversation management, message rendering   |

### Backend (hosted at `https://whisperbox.koyeb.app`)

- Stores user accounts with their RSA public key, wrapped private key, and PBKDF2 salt
- Stores message payloads as encrypted blobs with no access to the AES key or plaintext
- Manages JWT issuance, refresh, and revocation
- Routes real-time messages over WebSocket and stores undelivered messages for offline recipients

---

## Architecture Diagram

```
CLIENT (Browser)                          SERVER (whisperbox.koyeb.app)
────────────────────────────────────      ────────────────────────────────────

  app.js ──► crypto.js                    /auth/register
     │           │                              │
     │     Web Crypto API                       ▼
     │     (RSA-OAEP, AES-GCM,           stores:
     │      PBKDF2)                        - username
     │           │                         - public_key (RSA, plaintext)
     │      api.js ──── HTTPS ──────────►  - wrapped_private_key (AES-GCM ciphertext)
     │           │                         - pbkdf2_salt
     │           │                         - password hash (bcrypt, server-side)
     │      ws.js ────── WSS ────────────►
     │           │                       /ws (WebSocket)
  store.js       │                         - delivers message.receive events
     │           │                         - flushes undelivered messages on connect
     │
     ├── private key: JavaScript memory only (CryptoKey, non-extractable after unwrap)
     ├── access token: JavaScript memory only
     └── refresh token + user profile: sessionStorage (cleared on tab close)


SEND MESSAGE FLOW
─────────────────
Sender browser                                 Server            Recipient browser
──────────────                                 ──────            ─────────────────
1. generateAESKey()
2. encryptMessage(plaintext, aesKey) ──────────────────────────────────────────►
3. encryptAESKey(aesKey, recipientRSAPubKey)
4. encryptAESKey(aesKey, selfRSAPubKey)
5. WS: message.send { ciphertext, iv,
        encryptedKey, encryptedKeyForSelf } ──► store blob ──► message.receive event
                                                               6. decryptAESKey(encryptedKey,
                                                                    myRSAPrivateKey)
                                                               7. decryptMessage(ciphertext,
                                                                    iv, aesKey)
                                                               8. render plaintext
```

---

## Encryption Flow

### Registration

1. The browser generates a 2048-bit RSA-OAEP keypair using `window.crypto.subtle.generateKey`.
2. A random 128-bit salt is generated.
3. The user's password is stretched with PBKDF2 (310,000 iterations, SHA-256) to derive a 256-bit AES-GCM wrapping key.
4. The RSA private key is exported as PKCS8 and encrypted with AES-GCM using a 12-byte random IV. The IV is prepended to the ciphertext and the whole thing is base64-encoded as `wrapped_private_key`.
5. The RSA public key is exported as SPKI (base64) as `public_key`.
6. The browser sends `username`, `password`, `public_key`, `wrapped_private_key`, and `pbkdf2_salt` to `POST /auth/register`. The server hashes the password with bcrypt and stores everything else verbatim.

### Login / Session Restore

1. `POST /auth/login` returns the user's stored `wrapped_private_key` and `pbkdf2_salt` alongside JWT tokens.
2. The browser re-derives the AES-GCM wrapping key from the entered password and the returned salt (same PBKDF2 parameters).
3. The RSA private key is decrypted from `wrapped_private_key` and imported as a non-extractable `CryptoKey` held in JavaScript memory.
4. The key is never written to disk, `localStorage`, or any persistent store.
5. If the password is wrong, AES-GCM decryption throws, and the login is rejected before any token is accepted.

### Sending a Message

1. A fresh 256-bit AES-GCM key and a 12-byte IV are generated per message.
2. The plaintext is encrypted with AES-GCM, producing `ciphertext`.
3. The AES key is RSA-OAEP encrypted with the **recipient's public key**, producing `encryptedKey`. This allows only the recipient to recover the AES key.
4. The AES key is also RSA-OAEP encrypted with the **sender's own public key**, producing `encryptedKeyForSelf`. This allows the sender to read their own sent messages after the fact.
5. The four-field payload (`ciphertext`, `iv`, `encryptedKey`, `encryptedKeyForSelf`) is sent over WebSocket (`message.send`) or HTTP fallback (`POST /messages`). The server stores the payload without being able to inspect any field.

### Receiving a Message

1. The recipient receives a `message.receive` WebSocket event containing the encrypted payload.
2. `encryptedKey` is decrypted with the recipient's RSA private key (held in memory), recovering the AES-GCM key.
3. `ciphertext` is decrypted with the AES-GCM key and the stored `iv`, producing the original plaintext.
4. Decryption failure is caught and displayed as `[Failed to decrypt]` — the application never crashes silently.

---

## Key Management

### RSA Keypair

| Item                  | Where it lives                           | How it is protected                                               |
| --------------------- | ---------------------------------------- | ----------------------------------------------------------------- |
| Public key            | Server database + client memory          | Intentionally public — readable by any authenticated user         |
| Private key (in use)  | JavaScript `CryptoKey` object in memory  | Non-extractable after login unwrap; lost when tab closes          |
| Private key (at rest) | Server database as `wrapped_private_key` | AES-256-GCM encrypted with a key derived from the user's password |

The private key is imported with `extractable: false` after unwrapping, which means the Web Crypto API will not allow it to be exported or serialised again from within the browser. Even if an attacker gained access to the JavaScript heap, they cannot export the raw key bytes.

### PBKDF2 Parameters

| Parameter   | Value       | Reason                                               |
| ----------- | ----------- | ---------------------------------------------------- |
| Iterations  | 310,000     | OWASP 2023 minimum recommendation for PBKDF2-SHA-256 |
| Hash        | SHA-256     | Standard, widely supported                           |
| Salt length | 128 bits    | Prevents precomputed attacks per user                |
| Output key  | AES-256-GCM | 256-bit key for wrapping the private key             |

### AES-GCM vs AES-KW

The API guide suggests AES-KW for wrapping. This implementation uses AES-GCM instead. AES-KW requires the plaintext to be a multiple of 8 bytes; PKCS8-exported RSA private keys have variable-length DER encoding and are not guaranteed to satisfy this constraint. AES-GCM has no such requirement and provides authenticated encryption, so it is strictly more appropriate here. The server stores the blob opaquely either way.

### Token Lifecycle

| Token         | Storage                            | Lifetime          | Notes                              |
| ------------- | ---------------------------------- | ----------------- | ---------------------------------- |
| Access token  | JavaScript memory (`_accessToken`) | 15 minutes        | Lost on page close or refresh      |
| Refresh token | `sessionStorage`                   | Server-controlled | Cleared on logout and on tab close |

Access tokens are proactively refreshed 60 seconds before expiry to avoid a gap in WebSocket connectivity. `sessionStorage` is used instead of `localStorage` so the refresh token does not persist across browser sessions.

---

## Security Trade-offs

### Server-stored wrapped private key

The RSA private key is encrypted client-side with a key derived from the user's password and stored on the server alongside the PBKDF2 salt. This is necessary to allow users to recover their private key when logging in from the same device. The trade-off is that the server holds the data needed to attempt an offline brute-force attack against the password. This risk is mitigated by the 310,000-iteration PBKDF2 stretch and by the AES-GCM authentication tag, which makes incorrect password guesses detectable immediately and without a successful decryption.

### No forward secrecy

RSA-OAEP key exchange does not provide forward secrecy. If a user's private key were recovered at any point in the future, all past messages encrypted to that key could be decrypted. A forward-secret implementation would require a key-agreement protocol such as X3DH (used by Signal) with rotating ephemeral keys. This is noted as a known limitation.

### Session persistence within a tab

The refresh token is stored in `sessionStorage`, which means it survives a page reload within the same tab but is cleared when the tab is closed. On reload, the user is prompted for their password again to re-derive the private key. This is a deliberate trade-off: it avoids storing the session token permanently while not forcing a full re-authentication on every accidental refresh.

### No message deletion or revocation

Once a message payload is stored on the server, there is no mechanism to revoke or delete it. The server could theoretically retain ciphertexts indefinitely. A production system would require explicit message retention policies and server-side deletion APIs.

### Password transmitted to server on registration and login

The password is sent over HTTPS to the server for server-side bcrypt hashing. The server therefore sees the plaintext password in the request body during these two operations. This is consistent with standard web authentication practice and is acceptable when HTTPS is enforced, but it differs from zero-knowledge architectures where only a derived proof is sent.

---

## Known Limitations

- **No forward secrecy.** Compromise of a user's RSA private key exposes all past messages encrypted to that key. Mitigation would require ephemeral key agreement (for example, ECDH with rotating keys per conversation).

- **No multi-device support.** The private key is derived from the user's password and stored as a single wrapped blob. To use the application on a second device, the user logs in with the same credentials and the private key is re-derived. Messages sent to the user while logged in on another device are stored on the server and delivered on next connection, but all decryption still requires the password to be available.

- **No group messaging.** The current hybrid scheme encrypts one AES key per recipient. Group messaging would require encrypting the AES key for each group member individually, plus a group key management layer.

- **Public key trust is centralised.** The server distributes public keys. If the server were compromised, it could substitute an attacker's public key in place of a legitimate user's key (a key substitution attack). A production system would require key transparency logs or out-of-band key fingerprint verification.

- **New message notifications show user ID.** When a message arrives for a conversation that is not currently open, the toast notification displays the sender's UUID rather than their display name. This is a cosmetic defect in `app.js`.

- **WebSocket status dot overwritten.** The `app.js` file sets `ws-status` element's `textContent` directly, which removes the CSS-animated dot span added by the updated HTML. The connection status still switches CSS classes correctly so the colour indicator works, but the dot animation is lost.

- **No replay attack protection.** The AES-GCM IV is generated randomly per message. While a duplicate IV with the same key would break confidentiality, there is no server-side mechanism to reject replayed message payloads. Message IDs from the server are not validated against a client-side seen-set.

- **Session is lost on page close.** The private key is held only in JavaScript memory and is gone when the tab is closed. The user must re-enter their password after every browser session. This is intentional for security but may be inconvenient.

---

## Running Locally

The application is a static set of HTML and JavaScript files with no build step.

```bash
# Clone the repository
git clone https://github.com/<your-username>/whisperbox.git
cd whisperbox

# Serve with any static file server, for example:
npx serve .
# or
python3 -m http.server 5501
```

Open `http://localhost:5501` in the browser. The application connects to the live backend at `https://whisperbox.koyeb.app`.

---

## API Reference

Base URL: `https://whisperbox.koyeb.app`

Interactive docs: `https://whisperbox.koyeb.app/docs`

| Method | Path                           | Auth | Description                                        |
| ------ | ------------------------------ | ---- | -------------------------------------------------- |
| GET    | `/health`                      | No   | Server health check                                |
| POST   | `/auth/register`               | No   | Register, returns tokens and key material          |
| POST   | `/auth/login`                  | No   | Login, returns tokens and key material             |
| GET    | `/auth/me`                     | Yes  | Current user profile                               |
| POST   | `/auth/refresh`                | No   | Exchange refresh token for new access token        |
| POST   | `/auth/logout`                 | Yes  | Revoke refresh token                               |
| GET    | `/users/search?q=`             | Yes  | Search users by username or display name           |
| GET    | `/users/{id}/public-key`       | Yes  | Fetch a user's RSA public key                      |
| GET    | `/conversations`               | Yes  | List all conversations                             |
| GET    | `/conversations/{id}/messages` | Yes  | Paginated message history (newest first)           |
| POST   | `/messages`                    | Yes  | Send message via HTTP (WebSocket offline fallback) |
| WS     | `/ws?token=`                   | Yes  | Real-time messaging and presence                   |

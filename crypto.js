// ─── WhisperBox Crypto Layer ───────────────────────────────────────────────
// All encryption/decryption happens here. Server never sees plaintext.

const Crypto = (() => {
  const subtle = window.crypto.subtle;

  // ── Helpers ──────────────────────────────────────────────────────────────
  function randomBytes(n) {
    return window.crypto.getRandomValues(new Uint8Array(n));
  }

  function toB64(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let str = '';
    for (const b of bytes) str += String.fromCharCode(b);
    return btoa(str);
  }

  function fromB64(str) {
    const bin = atob(str);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf;
  }

  function strToBytes(str) { return new TextEncoder().encode(str); }
  function bytesToStr(buf) { return new TextDecoder().decode(buf); }

  // ── RSA-OAEP Key Generation ───────────────────────────────────────────────
  async function generateRSAKeyPair() {
    return subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['encrypt', 'decrypt']
    );
  }

  async function exportPublicKey(publicKey) {
    const spki = await subtle.exportKey('spki', publicKey);
    return toB64(spki);
  }

  async function importPublicKey(b64) {
    return subtle.importKey('spki', fromB64(b64), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
  }

  // ── PBKDF2 → AES-GCM (key from password) ─────────────────────────────────
  // We use AES-GCM (not AES-KW) because AES-KW requires plaintext to be a
  // multiple of 8 bytes — RSA pkcs8 exports aren't guaranteed to be.
  async function deriveEncryptionKey(password, saltBytes) {
    const passKey = await subtle.importKey('raw', strToBytes(password), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'PBKDF2', salt: saltBytes, iterations: 310_000, hash: 'SHA-256' },
      passKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // ── Wrap / Unwrap Private Key ─────────────────────────────────────────────
  // Stored format: base64( iv[12] || AES-GCM(pkcs8) )
  async function wrapPrivateKey(privateKey, password) {
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const encKey = await deriveEncryptionKey(password, salt);
    const pkcs8 = await subtle.exportKey('pkcs8', privateKey);
    const encrypted = await subtle.encrypt({ name: 'AES-GCM', iv }, encKey, pkcs8);

    // Combine iv + ciphertext into one blob
    const combined = new Uint8Array(12 + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), 12);

    return {
      wrappedPrivateKey: toB64(combined),
      pbkdf2Salt: toB64(salt),
    };
  }

  async function unwrapPrivateKey(wrappedB64, saltB64, password) {
    const salt = fromB64(saltB64);
    const encKey = await deriveEncryptionKey(password, salt);
    const combined = fromB64(wrappedB64);
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    const pkcs8 = await subtle.decrypt({ name: 'AES-GCM', iv }, encKey, ciphertext);
    return subtle.importKey('pkcs8', pkcs8, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
  }

  // ── AES-GCM Symmetric Encryption ─────────────────────────────────────────
  async function generateAESKey() {
    return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  async function encryptMessage(plaintext, aesKey) {
    const iv = randomBytes(12);
    const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, strToBytes(plaintext));
    return { ciphertext: toB64(ciphertext), iv: toB64(iv) };
  }

  async function decryptMessage(ciphertextB64, ivB64, aesKey) {
    const plaintext = await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(ivB64) }, aesKey, fromB64(ciphertextB64));
    return bytesToStr(plaintext);
  }

  // ── RSA-OAEP Encrypt/Decrypt AES key ─────────────────────────────────────
  async function encryptAESKeyWithRSA(aesKey, rsaPublicKey) {
    const rawAES = await subtle.exportKey('raw', aesKey);
    const encrypted = await subtle.encrypt({ name: 'RSA-OAEP' }, rsaPublicKey, rawAES);
    return toB64(encrypted);
  }

  async function decryptAESKeyWithRSA(encryptedKeyB64, rsaPrivateKey) {
    const rawAES = await subtle.decrypt({ name: 'RSA-OAEP' }, rsaPrivateKey, fromB64(encryptedKeyB64));
    return subtle.importKey('raw', rawAES, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  }

  // ── High-level: encrypt plaintext for a recipient ─────────────────────────
  async function encryptForRecipient(plaintext, recipientPublicKeyB64, selfPublicKeyB64) {
    const [recipientPubKey, selfPubKey] = await Promise.all([
      importPublicKey(recipientPublicKeyB64),
      importPublicKey(selfPublicKeyB64),
    ]);

    const aesKey = await generateAESKey();
    const { ciphertext, iv } = await encryptMessage(plaintext, aesKey);

    const [encryptedKey, encryptedKeyForSelf] = await Promise.all([
      encryptAESKeyWithRSA(aesKey, recipientPubKey),
      encryptAESKeyWithRSA(aesKey, selfPubKey),
    ]);

    return { ciphertext, iv, encryptedKey, encryptedKeyForSelf };
  }

  // ── High-level: decrypt a received payload ────────────────────────────────
  // isSender=true → use encryptedKeyForSelf
  async function decryptPayload(payload, privateKey, isSender = false) {
    const keyB64 = isSender ? payload.encryptedKeyForSelf : payload.encryptedKey;
    const aesKey = await decryptAESKeyWithRSA(keyB64, privateKey);
    return decryptMessage(payload.ciphertext, payload.iv, aesKey);
  }

  return {
    generateRSAKeyPair,
    exportPublicKey,
    importPublicKey,
    wrapPrivateKey,
    unwrapPrivateKey,
    encryptForRecipient,
    decryptPayload,
  };
})();

import {
  importECDHPublicKey,
  importECDSAPublicKey,
  exportPublicKey
} from './KeyManager.js';

const KEY_EXCHANGE_TIMEOUT = 30000;
const TIMESTAMP_TOLERANCE = 60000;

export function generateNonce() {
  const nonceBytes = new Uint8Array(32);
  window.crypto.getRandomValues(nonceBytes);
  return arrayBufferToBase64(nonceBytes.buffer);
}

export function getTimestamp() {
  return Date.now();
}

export function isTimestampValid(timestamp) {
  const now = Date.now();
  const diff = Math.abs(now - timestamp);
  return diff <= TIMESTAMP_TOLERANCE;
}

export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function createSignatureData(...values) {
  const encoder = new TextEncoder();
  const parts = values.map(v => {
    if (typeof v === 'object') {
      return encoder.encode(JSON.stringify(v));
    }
    return encoder.encode(String(v));
  });
  const totalLength = parts.reduce((sum, part) => sum + part.length, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    combined.set(part, offset);
    offset += part.length;
  }
  return combined.buffer;
}

export async function signData(privateKey, ...data) {
  const signatureData = createSignatureData(...data);
  const signature = await window.crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: { name: 'SHA-256' }
    },
    privateKey,
    signatureData
  );
  return arrayBufferToBase64(signature);
}

export async function verifySignature(publicKey, signature, ...data) {
  const signatureData = createSignatureData(...data);
  const signatureBuffer = base64ToArrayBuffer(signature);
  const isValid = await window.crypto.subtle.verify(
    {
      name: 'ECDSA',
      hash: { name: 'SHA-256' }
    },
    publicKey,
    signatureBuffer,
    signatureData
  );
  return isValid;
}

export async function deriveSharedSecret(privateKey, peerPublicKey) {
  const sharedBits = await window.crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: peerPublicKey
    },
    privateKey,
    256
  );
  return sharedBits;
}

export async function deriveSessionKey(sharedSecret, salt, info) {
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    sharedSecret,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );
  const encoder = new TextEncoder();
  const saltBuffer = typeof salt === 'string' ? encoder.encode(salt) : salt;
  const infoBuffer = typeof info === 'string' ? encoder.encode(info) : info;
  const sessionKey = await window.crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: saltBuffer,
      info: infoBuffer
    },
    keyMaterial,
    {
      name: 'AES-GCM',
      length: 256
    },
    true,
    ['encrypt', 'decrypt']
  );
  return sessionKey;
}

export function generateSessionId() {
  const bytes = new Uint8Array(16);
  window.crypto.getRandomValues(bytes);
  return arrayBufferToBase64(bytes.buffer);
}

export class KeyExchangeSession {
  constructor(myKeys, peerId) {
    this.myKeys = myKeys;
    this.peerId = peerId;
    this.sessionId = null;
    this.peerECDHPublicKey = null;
    this.peerECDSAPublicKey = null;
    this.sessionKey = null;
    this.state = 'IDLE';
    this.myNonce = null;
    this.peerNonce = null;
    this.startTime = null;
  }

  async createInitMessage() {
    this.state = 'INITIATED';
    this.startTime = Date.now();
    this.myNonce = generateNonce();
    this.sessionId = generateSessionId();
    const timestamp = getTimestamp();
    const myECDHPublicKey = await exportPublicKey(this.myKeys.ecdhKeyPair.publicKey);
    const myECDSAPublicKey = await exportPublicKey(this.myKeys.ecdsaKeyPair.publicKey);
    const signature = await signData(
      this.myKeys.ecdsaKeyPair.privateKey,
      myECDHPublicKey,
      timestamp,
      this.myNonce
    );
    return {
      type: 'KEY_EXCHANGE_INIT',
      sessionId: this.sessionId,
      senderPublicKey: myECDHPublicKey,
      senderSigningKey: myECDSAPublicKey,
      timestamp,
      nonce: this.myNonce,
      signature
    };
  }

  async processInitMessage(initMessage) {
    if (!isTimestampValid(initMessage.timestamp)) {
      throw new Error('KEY_EXCHANGE_FAILED: Timestamp out of range (possible replay attack)');
    }
    this.peerECDHPublicKey = await importECDHPublicKey(initMessage.senderPublicKey);
    this.peerECDSAPublicKey = await importECDSAPublicKey(initMessage.senderSigningKey);
    const isSignatureValid = await verifySignature(
      this.peerECDSAPublicKey,
      initMessage.signature,
      initMessage.senderPublicKey,
      initMessage.timestamp,
      initMessage.nonce
    );
    if (!isSignatureValid) {
      throw new Error('KEY_EXCHANGE_FAILED: Invalid signature (possible MITM attack)');
    }
    this.sessionId = initMessage.sessionId;
    this.peerNonce = initMessage.nonce;
    this.state = 'RESPONDED';
    this.startTime = Date.now();
    this.myNonce = generateNonce();
    const timestamp = getTimestamp();
    const myECDHPublicKey = await exportPublicKey(this.myKeys.ecdhKeyPair.publicKey);
    const myECDSAPublicKey = await exportPublicKey(this.myKeys.ecdsaKeyPair.publicKey);
    const signature = await signData(
      this.myKeys.ecdsaKeyPair.privateKey,
      myECDHPublicKey,
      timestamp,
      this.myNonce,
      this.peerNonce
    );
    return {
      type: 'KEY_EXCHANGE_RESPONSE',
      sessionId: this.sessionId,
      responderPublicKey: myECDHPublicKey,
      responderSigningKey: myECDSAPublicKey,
      timestamp,
      nonce: this.myNonce,
      originalNonce: this.peerNonce,
      signature
    };
  }

  async processResponseMessage(responseMessage) {
    if (responseMessage.sessionId !== this.sessionId) {
      throw new Error('KEY_EXCHANGE_FAILED: Session ID mismatch');
    }
    if (!isTimestampValid(responseMessage.timestamp)) {
      throw new Error('KEY_EXCHANGE_FAILED: Timestamp out of range (possible replay attack)');
    }
    if (responseMessage.originalNonce !== this.myNonce) {
      throw new Error('KEY_EXCHANGE_FAILED: Nonce mismatch (possible MITM attack)');
    }
    this.peerECDHPublicKey = await importECDHPublicKey(responseMessage.responderPublicKey);
    this.peerECDSAPublicKey = await importECDSAPublicKey(responseMessage.responderSigningKey);
    const isSignatureValid = await verifySignature(
      this.peerECDSAPublicKey,
      responseMessage.signature,
      responseMessage.responderPublicKey,
      responseMessage.timestamp,
      responseMessage.nonce,
      responseMessage.originalNonce
    );
    if (!isSignatureValid) {
      throw new Error('KEY_EXCHANGE_FAILED: Invalid signature (possible MITM attack)');
    }
    this.peerNonce = responseMessage.nonce;
    this.state = 'RESPONDED';
    return true;
  }

  async createKeyConfirmation() {
    if (!this.peerECDHPublicKey) {
      throw new Error('Cannot derive key: peer public key not set');
    }
    const sharedSecret = await deriveSharedSecret(
      this.myKeys.ecdhKeyPair.privateKey,
      this.peerECDHPublicKey
    );
    const nonces = [this.myNonce, this.peerNonce].sort();
    const salt = `${nonces[0]}:${nonces[1]}`;
    const info = `SecureMessaging:SessionKey:${this.sessionId}`;
    this.sessionKey = await deriveSessionKey(sharedSecret, salt, info);
    const confirmData = `KEY_CONFIRM:${this.sessionId}:${this.myNonce}`;
    const encoder = new TextEncoder();
    const confirmBytes = encoder.encode(confirmData);
    const iv = new Uint8Array(12);
    window.crypto.getRandomValues(iv);
    const encryptedConfirm = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      this.sessionKey,
      confirmBytes
    );
    return {
      type: 'KEY_CONFIRM',
      sessionId: this.sessionId,
      iv: arrayBufferToBase64(iv.buffer),
      confirmation: arrayBufferToBase64(encryptedConfirm)
    };
  }

  async verifyKeyConfirmation(confirmMessage) {
    if (confirmMessage.sessionId !== this.sessionId) {
      throw new Error('KEY_CONFIRM_FAILED: Session ID mismatch');
    }
    if (!this.sessionKey) {
      await this.createKeyConfirmation();
    }
    const iv = new Uint8Array(base64ToArrayBuffer(confirmMessage.iv));
    const encryptedData = base64ToArrayBuffer(confirmMessage.confirmation);
    try {
      const decrypted = await window.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv
        },
        this.sessionKey,
        encryptedData
      );
      const decoder = new TextDecoder();
      const confirmText = decoder.decode(decrypted);
      if (!confirmText.startsWith('KEY_CONFIRM:') || !confirmText.includes(this.sessionId)) {
        throw new Error('Invalid confirmation format');
      }
      this.state = 'CONFIRMED';
      return true;
    } catch (error) {
      throw new Error('KEY_CONFIRM_FAILED: Could not decrypt confirmation (key mismatch)');
    }
  }

  getSessionKey() {
    if (this.state !== 'CONFIRMED') {
      throw new Error('Session key not available: key exchange not confirmed');
    }
    return this.sessionKey;
  }

  isTimedOut() {
    if (!this.startTime) return false;
    return (Date.now() - this.startTime) > KEY_EXCHANGE_TIMEOUT;
  }

  getState() {
    return {
      sessionId: this.sessionId,
      peerId: this.peerId,
      state: this.state,
      hasPeerPublicKey: !!this.peerECDHPublicKey,
      hasSessionKey: !!this.sessionKey,
      startTime: this.startTime
    };
  }
}

export async function demonstrateMITMVulnerability() {
  console.log('=== MITM ATTACK DEMONSTRATION ===');
  console.log('Without digital signatures, ECDH is vulnerable to MITM attacks.');
  console.log('');
  console.log('Attack Scenario:');
  console.log('1. Alice wants to establish a session with Bob');
  console.log('2. Mallory (attacker) intercepts Alice\'s public key');
  console.log('3. Mallory sends her own public key to Bob, pretending to be Alice');
  console.log('4. Mallory intercepts Bob\'s public key');
  console.log('5. Mallory sends her own public key to Alice, pretending to be Bob');
  console.log('6. Now Mallory has two session keys:');
  console.log('   - One with Alice (Alice thinks it\'s with Bob)');
  console.log('   - One with Bob (Bob thinks it\'s with Alice)');
  console.log('7. Mallory can decrypt, read, modify, and re-encrypt all messages');
  console.log('');
  console.log('SOLUTION: Digital signatures ensure authenticity of public keys.');
  console.log('Each party signs their ECDH public key with their ECDSA private key.');
  console.log('Mallory cannot forge valid signatures, so the attack fails.');
  return {
    vulnerable: 'Plain ECDH without authentication',
    secure: 'ECDH with ECDSA signatures (our implementation)',
    mitigation: 'Verify signatures before deriving shared secret'
  };
}

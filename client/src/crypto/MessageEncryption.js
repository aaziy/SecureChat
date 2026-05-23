import { arrayBufferToBase64, base64ToArrayBuffer, generateNonce, getTimestamp } from './KeyExchange.js';

const IV_LENGTH = 12;
const MESSAGE_EXPIRY = 300000;

export class MessageSequenceTracker {
  constructor() {
    this.peerState = new Map();
    this.outgoingSequence = 0;
    this.usedNonces = new Set();
    this.maxNonces = 10000;
  }

  getNextSequence() {
    return ++this.outgoingSequence;
  }

  validateIncoming(peerId, sequenceNumber, nonce, timestamp) {
    const now = Date.now();
    if (Math.abs(now - timestamp) > MESSAGE_EXPIRY) {
      throw new Error('REPLAY_DETECTED: Message timestamp expired');
    }
    if (this.usedNonces.has(nonce)) {
      throw new Error('REPLAY_DETECTED: Duplicate nonce');
    }
    if (!this.peerState.has(peerId)) {
      this.peerState.set(peerId, {
        lastSequence: 0,
        receivedNonces: new Set()
      });
    }
    const state = this.peerState.get(peerId);
    if (sequenceNumber <= state.lastSequence) {
      throw new Error(`REPLAY_DETECTED: Sequence number ${sequenceNumber} <= last ${state.lastSequence}`);
    }
    state.lastSequence = sequenceNumber;
    state.receivedNonces.add(nonce);
    this.usedNonces.add(nonce);
    if (this.usedNonces.size > this.maxNonces) {
      const noncesArray = Array.from(this.usedNonces);
      this.usedNonces = new Set(noncesArray.slice(-this.maxNonces / 2));
    }
    return true;
  }

  reset() {
    this.peerState.clear();
    this.outgoingSequence = 0;
    this.usedNonces.clear();
  }

  getState() {
    const peerStates = {};
    for (const [peerId, state] of this.peerState) {
      peerStates[peerId] = {
        lastSequence: state.lastSequence,
        nonceCount: state.receivedNonces.size
      };
    }
    return {
      outgoingSequence: this.outgoingSequence,
      totalNonces: this.usedNonces.size,
      peerStates
    };
  }
}

export function generateMessageId() {
  const bytes = new Uint8Array(16);
  window.crypto.getRandomValues(bytes);
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

export function generateIV() {
  const iv = new Uint8Array(IV_LENGTH);
  window.crypto.getRandomValues(iv);
  return iv;
}

export async function encryptMessage(sessionKey, plaintext, sequenceTracker) {
  const iv = generateIV();
  const messageId = generateMessageId();
  const timestamp = getTimestamp();
  const sequenceNumber = sequenceTracker.getNextSequence();
  const nonce = generateNonce();
  const payload = {
    content: plaintext,
    messageId,
    timestamp,
    sequenceNumber,
    nonce
  };
  const encoder = new TextEncoder();
  const payloadBytes = encoder.encode(JSON.stringify(payload));
  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      additionalData: encoder.encode(`${messageId}:${timestamp}:${sequenceNumber}`)
    },
    sessionKey,
    payloadBytes
  );
  return {
    messageId,
    iv: arrayBufferToBase64(iv.buffer),
    ciphertext: arrayBufferToBase64(ciphertext),
    timestamp,
    sequenceNumber,
    nonce
  };
}

export async function decryptMessage(sessionKey, encryptedMessage, senderId, sequenceTracker) {
  const { messageId, iv, ciphertext, timestamp, sequenceNumber, nonce } = encryptedMessage;
  sequenceTracker.validateIncoming(senderId, sequenceNumber, nonce, timestamp);
  const ivBytes = new Uint8Array(base64ToArrayBuffer(iv));
  const ciphertextBytes = base64ToArrayBuffer(ciphertext);
  const encoder = new TextEncoder();
  const aad = encoder.encode(`${messageId}:${timestamp}:${sequenceNumber}`);
  try {
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivBytes,
        additionalData: aad
      },
      sessionKey,
      ciphertextBytes
    );
    const decoder = new TextDecoder();
    const payloadStr = decoder.decode(decrypted);
    const payload = JSON.parse(payloadStr);
    if (payload.messageId !== messageId ||
        payload.timestamp !== timestamp ||
        payload.sequenceNumber !== sequenceNumber ||
        payload.nonce !== nonce) {
      throw new Error('INTEGRITY_ERROR: Payload metadata mismatch');
    }
    return {
      content: payload.content,
      messageId: payload.messageId,
      timestamp: payload.timestamp,
      verified: true
    };
  } catch (error) {
    if (error.name === 'OperationError') {
      throw new Error('DECRYPTION_FAILED: Authentication failed (message tampered or wrong key)');
    }
    throw error;
  }
}

export async function encryptFile(sessionKey, fileData, fileName, mimeType) {
  const iv = generateIV();
  const metadata = {
    fileName,
    mimeType,
    size: fileData.byteLength,
    timestamp: getTimestamp(),
    nonce: generateNonce()
  };
  const encoder = new TextEncoder();
  const metadataBytes = encoder.encode(JSON.stringify(metadata));
  const encryptedData = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      additionalData: metadataBytes
    },
    sessionKey,
    fileData
  );
  const metadataIv = generateIV();
  const encryptedMetadata = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: metadataIv
    },
    sessionKey,
    metadataBytes
  );
  return {
    iv: arrayBufferToBase64(iv.buffer),
    encryptedData: arrayBufferToBase64(encryptedData),
    metadataIv: arrayBufferToBase64(metadataIv.buffer),
    encryptedMetadata: arrayBufferToBase64(encryptedMetadata),
    timestamp: metadata.timestamp
  };
}

export async function decryptFile(sessionKey, encryptedFile) {
  const { iv, encryptedData, metadataIv, encryptedMetadata } = encryptedFile;
  const metadataIvBytes = new Uint8Array(base64ToArrayBuffer(metadataIv));
  const encryptedMetadataBytes = base64ToArrayBuffer(encryptedMetadata);
  let metadata;
  try {
    const decryptedMetadata = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: metadataIvBytes
      },
      sessionKey,
      encryptedMetadataBytes
    );
    const decoder = new TextDecoder();
    metadata = JSON.parse(decoder.decode(decryptedMetadata));
  } catch (error) {
    throw new Error('FILE_DECRYPTION_FAILED: Could not decrypt metadata');
  }
  const ivBytes = new Uint8Array(base64ToArrayBuffer(iv));
  const encryptedDataBytes = base64ToArrayBuffer(encryptedData);
  const encoder = new TextEncoder();
  const metadataBytes = encoder.encode(JSON.stringify(metadata));
  try {
    const decryptedData = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivBytes,
        additionalData: metadataBytes
      },
      sessionKey,
      encryptedDataBytes
    );
    return {
      data: decryptedData,
      fileName: metadata.fileName,
      mimeType: metadata.mimeType,
      size: metadata.size,
      timestamp: metadata.timestamp
    };
  } catch (error) {
    throw new Error('FILE_DECRYPTION_FAILED: Authentication failed (file tampered or wrong key)');
  }
}

export function createMessageEnvelope(encryptedMessage, senderId, recipientId) {
  return {
    type: 'ENCRYPTED_MESSAGE',
    senderId,
    recipientId,
    payload: encryptedMessage,
    transmissionTime: getTimestamp()
  };
}

export function validateMessageEnvelope(envelope) {
  const required = ['type', 'senderId', 'recipientId', 'payload'];
  for (const field of required) {
    if (!envelope[field]) {
      throw new Error(`Invalid envelope: missing ${field}`);
    }
  }
  const payloadRequired = ['messageId', 'iv', 'ciphertext', 'timestamp', 'sequenceNumber', 'nonce'];
  for (const field of payloadRequired) {
    if (envelope.payload[field] === undefined) {
      throw new Error(`Invalid payload: missing ${field}`);
    }
  }
  return true;
}

export function demonstrateReplayProtection() {
  console.log('=== REPLAY ATTACK PROTECTION DEMONSTRATION ===');
  console.log('');
  console.log('Replay Attack Scenario:');
  console.log('1. Attacker captures a valid encrypted message from Alice to Bob');
  console.log('2. Later, attacker resends the same message to Bob');
  console.log('3. Without protection, Bob would process it again');
  console.log('');
  console.log('Our Protection Mechanisms:');
  console.log('');
  console.log('1. TIMESTAMPS:');
  console.log('   - Each message has a timestamp');
  console.log('   - Messages older than 5 minutes are rejected');
  console.log('   - Prevents replaying old messages');
  console.log('');
  console.log('2. SEQUENCE NUMBERS:');
  console.log('   - Each message has a monotonically increasing sequence number');
  console.log('   - If sequence number <= last received, message is rejected');
  console.log('   - Prevents replaying recent messages');
  console.log('');
  console.log('3. NONCES:');
  console.log('   - Each message has a random 256-bit nonce');
  console.log('   - Nonces are tracked and duplicates rejected');
  console.log('   - Additional layer of protection');
  console.log('');
  console.log('4. ADDITIONAL AUTHENTICATED DATA (AAD):');
  console.log('   - messageId, timestamp, sequenceNumber included in AAD');
  console.log('   - Any modification causes decryption to fail');
  console.log('   - Attacker cannot modify metadata');
  return {
    protections: ['timestamps', 'sequenceNumbers', 'nonces', 'AAD'],
    expiryTime: MESSAGE_EXPIRY,
    result: 'Replayed messages are detected and rejected'
  };
}

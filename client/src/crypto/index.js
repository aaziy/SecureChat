export {
  generateUserKeys,
  generateECDHKeyPair,
  generateECDSAKeyPair,
  exportPublicKey,
  exportPrivateKey,
  importECDHPublicKey,
  importECDHPrivateKey,
  importECDSAPublicKey,
  importECDSAPrivateKey,
  storeKeys,
  retrieveKeys,
  deleteKeys
} from './KeyManager.js';

export {
  KeyExchangeSession,
  generateNonce,
  getTimestamp,
  isTimestampValid,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  signData,
  verifySignature,
  deriveSharedSecret,
  deriveSessionKey,
  generateSessionId,
  demonstrateMITMVulnerability
} from './KeyExchange.js';

export {
  encryptMessage,
  decryptMessage,
  encryptFile,
  decryptFile,
  MessageSequenceTracker,
  generateMessageId,
  generateIV,
  createMessageEnvelope,
  validateMessageEnvelope,
  demonstrateReplayProtection
} from './MessageEncryption.js';

export {
  SecureMessaging,
  SecurityLogger,
  PeerSession
} from './SecureMessaging.js';

export {
  runAllTests,
  testKeyGeneration,
  testDigitalSignatures,
  testKeyExchange,
  testMITMAttack,
  testMessageEncryption,
  testReplayProtection,
  testFileEncryption,
  testFullIntegration
} from './CryptoTest.js';

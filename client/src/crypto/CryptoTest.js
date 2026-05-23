import { generateUserKeys, exportPublicKey } from './KeyManager.js';
import {
  KeyExchangeSession,
  generateNonce,
  arrayBufferToBase64,
  signData,
  verifySignature,
  deriveSharedSecret,
  deriveSessionKey
} from './KeyExchange.js';
import {
  encryptMessage,
  decryptMessage,
  encryptFile,
  decryptFile,
  MessageSequenceTracker,
  generateIV
} from './MessageEncryption.js';
import { SecureMessaging } from './SecureMessaging.js';

const testResults = {
  passed: 0,
  failed: 0,
  tests: []
};

function logTest(name, passed, details = {}) {
  const result = {
    name,
    passed,
    details,
    timestamp: new Date().toISOString()
  };
  testResults.tests.push(result);
  if (passed) {
    testResults.passed++;
    console.log(`✅ PASS: ${name}`);
  } else {
    testResults.failed++;
    console.log(`❌ FAIL: ${name}`, details);
  }
  return passed;
}

async function testKeyGeneration() {
  console.log('\n========== TEST: Key Generation ==========\n');
  try {
    const { keyPairs, publicKeys } = await generateUserKeys();
    const ecdhPubKey = keyPairs.ecdhKeyPair.publicKey;
    const ecdhPrivKey = keyPairs.ecdhKeyPair.privateKey;
    logTest('ECDH public key generated',
      ecdhPubKey.type === 'public' && ecdhPubKey.algorithm.name === 'ECDH',
      { algorithm: ecdhPubKey.algorithm }
    );
    logTest('ECDH private key generated',
      ecdhPrivKey.type === 'private' && ecdhPrivKey.algorithm.name === 'ECDH',
      { algorithm: ecdhPrivKey.algorithm }
    );
    const ecdsaPubKey = keyPairs.ecdsaKeyPair.publicKey;
    const ecdsaPrivKey = keyPairs.ecdsaKeyPair.privateKey;
    logTest('ECDSA public key generated',
      ecdsaPubKey.type === 'public' && ecdsaPubKey.algorithm.name === 'ECDSA',
      { algorithm: ecdsaPubKey.algorithm }
    );
    logTest('ECDSA private key generated',
      ecdsaPrivKey.type === 'private' && ecdsaPrivKey.algorithm.name === 'ECDSA',
      { algorithm: ecdsaPrivKey.algorithm }
    );
    logTest('Public keys exported to JWK format',
      publicKeys.ecdhPublicKey.kty === 'EC' && publicKeys.ecdsaPublicKey.kty === 'EC',
      { ecdhJWK: publicKeys.ecdhPublicKey, ecdsaJWK: publicKeys.ecdsaPublicKey }
    );
    console.log('\n📋 Exported ECDH Public Key (JWK):');
    console.log(JSON.stringify(publicKeys.ecdhPublicKey, null, 2));
    console.log('\n📋 Exported ECDSA Public Key (JWK):');
    console.log(JSON.stringify(publicKeys.ecdsaPublicKey, null, 2));
    return keyPairs;
  } catch (error) {
    logTest('Key generation', false, { error: error.message });
    throw error;
  }
}

async function testDigitalSignatures(aliceKeys) {
  console.log('\n========== TEST: Digital Signatures ==========\n');
  try {
    const testMessage = 'This is a test message to sign';
    const timestamp = Date.now();
    const nonce = generateNonce();
    const signature = await signData(
      aliceKeys.ecdsaKeyPair.privateKey,
      testMessage,
      timestamp,
      nonce
    );
    logTest('Signature created',
      typeof signature === 'string' && signature.length > 0,
      { signatureLength: signature.length }
    );
    const validResult = await verifySignature(
      aliceKeys.ecdsaKeyPair.publicKey,
      signature,
      testMessage,
      timestamp,
      nonce
    );
    logTest('Valid signature verification', validResult === true);
    const tamperedResult = await verifySignature(
      aliceKeys.ecdsaKeyPair.publicKey,
      signature,
      'Tampered message',
      timestamp,
      nonce
    );
    logTest('Tampered message detection', tamperedResult === false);
    const { keyPairs: bobKeys } = await generateUserKeys();
    const wrongKeyResult = await verifySignature(
      bobKeys.ecdsaKeyPair.publicKey,
      signature,
      testMessage,
      timestamp,
      nonce
    );
    logTest('Wrong key detection', wrongKeyResult === false);
    console.log('\n📋 Signature (base64):', signature.substring(0, 64) + '...');
    return true;
  } catch (error) {
    logTest('Digital signatures', false, { error: error.message });
    throw error;
  }
}

async function testKeyExchange() {
  console.log('\n========== TEST: ECDH Key Exchange with Signatures ==========\n');
  try {
    const { keyPairs: aliceKeys } = await generateUserKeys();
    const { keyPairs: bobKeys } = await generateUserKeys();
    console.log('👤 Alice and Bob generated their key pairs');
    const aliceSession = new KeyExchangeSession(aliceKeys, 'bob');
    const bobSession = new KeyExchangeSession(bobKeys, 'alice');
    console.log('\n--- Step 1: Alice initiates key exchange ---');
    const initMessage = await aliceSession.createInitMessage();
    logTest('Init message created',
      initMessage.type === 'KEY_EXCHANGE_INIT' && initMessage.signature,
      { sessionId: initMessage.sessionId }
    );
    console.log('📤 Alice sends init message with signed ECDH public key');
    console.log('   Session ID:', initMessage.sessionId);
    console.log('   Timestamp:', initMessage.timestamp);
    console.log('   Nonce:', initMessage.nonce.substring(0, 20) + '...');
    console.log('\n--- Step 2: Bob verifies signature and responds ---');
    const responseMessage = await bobSession.processInitMessage(initMessage);
    logTest('Bob verified Alice\'s signature', true);
    logTest('Response message created',
      responseMessage.type === 'KEY_EXCHANGE_RESPONSE' && responseMessage.signature,
      { originalNonce: responseMessage.originalNonce === initMessage.nonce }
    );
    console.log('📤 Bob sends response with his signed ECDH public key');
    console.log('   Original nonce echoed:', responseMessage.originalNonce.substring(0, 20) + '...');
    console.log('\n--- Step 3: Alice verifies Bob\'s signature ---');
    await aliceSession.processResponseMessage(responseMessage);
    logTest('Alice verified Bob\'s signature', true);
    logTest('Nonce verification passed', true);
    console.log('\n--- Step 4: Derive session keys and confirm ---');
    const aliceConfirm = await aliceSession.createKeyConfirmation();
    const bobConfirm = await bobSession.createKeyConfirmation();
    await bobSession.verifyKeyConfirmation(aliceConfirm);
    await aliceSession.verifyKeyConfirmation(bobConfirm);
    logTest('Alice confirmed Bob\'s key', aliceSession.state === 'CONFIRMED');
    logTest('Bob confirmed Alice\'s key', bobSession.state === 'CONFIRMED');
    const aliceSessionKey = aliceSession.getSessionKey();
    const bobSessionKey = bobSession.getSessionKey();
    const aliceKeyRaw = await window.crypto.subtle.exportKey('raw', aliceSessionKey);
    const bobKeyRaw = await window.crypto.subtle.exportKey('raw', bobSessionKey);
    const keysMatch = arrayBufferToBase64(aliceKeyRaw) === arrayBufferToBase64(bobKeyRaw);
    logTest('Session keys match', keysMatch);
    console.log('\n✅ Key exchange completed successfully!');
    console.log('📋 Session key (base64):', arrayBufferToBase64(aliceKeyRaw).substring(0, 32) + '...');
    return { aliceSession, bobSession, aliceKeys, bobKeys };
  } catch (error) {
    logTest('Key exchange', false, { error: error.message });
    throw error;
  }
}

async function testMITMAttack() {
  console.log('\n========== TEST: MITM Attack Demonstration ==========\n');
  console.log('🔴 SCENARIO: MITM Attack WITHOUT Digital Signatures');
  console.log('─'.repeat(50));
  console.log('');
  console.log('Without signatures, an attacker (Mallory) can:');
  console.log('1. Intercept Alice\'s ECDH public key');
  console.log('2. Send her own public key to Bob (pretending to be Alice)');
  console.log('3. Intercept Bob\'s ECDH public key');
  console.log('4. Send her own public key to Alice (pretending to be Bob)');
  console.log('');
  console.log('Result: Mallory shares a secret with both Alice and Bob!');
  console.log('        She can decrypt, read, modify, and re-encrypt all messages.');
  console.log('');
  const { keyPairs: aliceKeys } = await generateUserKeys();
  const { keyPairs: bobKeys } = await generateUserKeys();
  const { keyPairs: malloryKeys } = await generateUserKeys();
  const alicePublicKey = await exportPublicKey(aliceKeys.ecdhKeyPair.publicKey);
  const malloryPublicKey = await exportPublicKey(malloryKeys.ecdhKeyPair.publicKey);
  console.log('👤 Alice\'s public key:', alicePublicKey.x.substring(0, 20) + '...');
  console.log('😈 Mallory\'s public key:', malloryPublicKey.x.substring(0, 20) + '...');
  console.log('');
  console.log('In an unsigned exchange, Bob cannot tell the difference!');
  logTest('MITM attack demonstrated (educational)', true);
  console.log('\n🟢 SOLUTION: Digital Signatures');
  console.log('─'.repeat(50));
  console.log('');
  console.log('With our implementation:');
  console.log('1. Alice signs her ECDH public key with her ECDSA private key');
  console.log('2. Bob verifies the signature using Alice\'s known ECDSA public key');
  console.log('3. Mallory cannot forge Alice\'s signature (doesn\'t have private key)');
  console.log('4. The attack is detected and rejected!');
  console.log('');
  try {
    const { keyPairs: realAlice } = await generateUserKeys();
    const { keyPairs: realBob } = await generateUserKeys();
    const { keyPairs: mallory } = await generateUserKeys();
    const aliceSession = new KeyExchangeSession(realAlice, 'bob');
    const initMessage = await aliceSession.createInitMessage();
    const forgedMessage = {
      ...initMessage,
      senderPublicKey: await exportPublicKey(mallory.ecdhKeyPair.publicKey)
    };
    const bobSession = new KeyExchangeSession(realBob, 'alice');
    try {
      await bobSession.processInitMessage(forgedMessage);
      logTest('MITM detection (signature verification)', false, { error: 'Should have failed!' });
    } catch (error) {
      logTest('MITM detection (signature verification)',
        error.message.includes('Invalid signature'),
        { error: error.message }
      );
      console.log('\n✅ MITM attack detected and blocked!');
      console.log('   Error:', error.message);
    }
  } catch (error) {
    logTest('MITM demonstration', false, { error: error.message });
  }
  return true;
}

async function testMessageEncryption(aliceSession, bobSession) {
  console.log('\n========== TEST: Message Encryption (AES-256-GCM) ==========\n');
  try {
    const aliceKey = aliceSession.getSessionKey();
    const bobKey = bobSession.getSessionKey();
    const aliceTracker = new MessageSequenceTracker();
    const bobTracker = new MessageSequenceTracker();
    const testMessages = [
      'Hello Bob! This is a secret message.',
      'Here is some sensitive data: Credit Card 4111-1111-1111-1111',
      'Multi-line message:\nLine 1\nLine 2\nLine 3',
      '🔐 Unicode test: 你好世界 مرحبا العالم'
    ];
    for (let i = 0; i < testMessages.length; i++) {
      const plaintext = testMessages[i];
      console.log(`\n--- Message ${i + 1} ---`);
      console.log('📝 Original:', plaintext.substring(0, 50) + (plaintext.length > 50 ? '...' : ''));
      const encrypted = await encryptMessage(aliceKey, plaintext, aliceTracker);
      console.log('🔐 Encrypted:');
      console.log('   IV:', encrypted.iv.substring(0, 24) + '...');
      console.log('   Ciphertext:', encrypted.ciphertext.substring(0, 40) + '...');
      console.log('   Sequence:', encrypted.sequenceNumber);
      console.log('   Timestamp:', new Date(encrypted.timestamp).toISOString());
      logTest(`Message ${i + 1} encrypted`,
        encrypted.ciphertext && encrypted.iv && encrypted.nonce,
        { sequenceNumber: encrypted.sequenceNumber }
      );
      const decrypted = await decryptMessage(bobKey, encrypted, 'alice', bobTracker);
      console.log('📬 Decrypted:', decrypted.content.substring(0, 50) + (decrypted.content.length > 50 ? '...' : ''));
      logTest(`Message ${i + 1} decrypted correctly`,
        decrypted.content === plaintext && decrypted.verified,
        { verified: decrypted.verified }
      );
    }
    console.log('\n--- Tampering Detection Test ---');
    const originalEncrypted = await encryptMessage(aliceKey, 'Test message', aliceTracker);
    const tamperedEncrypted = {
      ...originalEncrypted,
      ciphertext: originalEncrypted.ciphertext.substring(0, 10) + 'XXXXX' + originalEncrypted.ciphertext.substring(15)
    };
    try {
      await decryptMessage(bobKey, tamperedEncrypted, 'alice', bobTracker);
      logTest('Tampering detection', false, { error: 'Should have failed!' });
    } catch (error) {
      logTest('Tampering detection',
        error.message.includes('DECRYPTION_FAILED') || error.message.includes('REPLAY'),
        { error: error.message }
      );
      console.log('✅ Tampered message detected and rejected!');
    }
    return true;
  } catch (error) {
    logTest('Message encryption', false, { error: error.message });
    throw error;
  }
}

async function testReplayProtection(aliceSession, bobSession) {
  console.log('\n========== TEST: Replay Attack Protection ==========\n');
  try {
    const aliceKey = aliceSession.getSessionKey();
    const bobKey = bobSession.getSessionKey();
    const aliceTracker = new MessageSequenceTracker();
    const bobTracker = new MessageSequenceTracker();
    console.log('--- Normal Message Flow ---');
    const message1 = await encryptMessage(aliceKey, 'First message', aliceTracker);
    const message2 = await encryptMessage(aliceKey, 'Second message', aliceTracker);
    const message3 = await encryptMessage(aliceKey, 'Third message', aliceTracker);
    console.log('📤 Alice sends messages with sequence numbers:',
      message1.sequenceNumber, message2.sequenceNumber, message3.sequenceNumber);
    await decryptMessage(bobKey, message1, 'alice', bobTracker);
    await decryptMessage(bobKey, message2, 'alice', bobTracker);
    await decryptMessage(bobKey, message3, 'alice', bobTracker);
    logTest('Normal message flow', true);
    console.log('📥 Bob received all messages successfully');
    console.log('\n--- Replay Attack: Duplicate Message ---');
    console.log('😈 Attacker captures message1 and replays it');
    try {
      await decryptMessage(bobKey, message1, 'alice', bobTracker);
      logTest('Replay attack (duplicate) detected', false);
    } catch (error) {
      logTest('Replay attack (duplicate) detected',
        error.message.includes('REPLAY'),
        { error: error.message }
      );
      console.log('✅ Replay detected! Error:', error.message);
    }
    console.log('\n--- Replay Attack: Old Sequence Number ---');
    const newBobTracker = new MessageSequenceTracker();
    await decryptMessage(bobKey, message3, 'alice', newBobTracker);
    console.log('📥 Bob receives message with seq=3');
    console.log('😈 Attacker replays message with seq=2');
    try {
      await decryptMessage(bobKey, message2, 'alice', newBobTracker);
      logTest('Replay attack (old sequence) detected', false);
    } catch (error) {
      logTest('Replay attack (old sequence) detected',
        error.message.includes('REPLAY'),
        { error: error.message }
      );
      console.log('✅ Old sequence detected! Error:', error.message);
    }
    console.log('\n--- Replay Attack: Expired Timestamp ---');
    console.log('😈 Attacker replays message captured 10 minutes ago');
    const freshTracker = new MessageSequenceTracker();
    const oldMessage = {
      ...message1,
      timestamp: Date.now() - 600000,
      nonce: generateNonce(),
      sequenceNumber: 999
    };
    try {
      await decryptMessage(bobKey, oldMessage, 'alice', freshTracker);
      logTest('Replay attack (expired timestamp) detected', false);
    } catch (error) {
      logTest('Replay attack (expired timestamp) detected',
        error.message.includes('REPLAY') || error.message.includes('timestamp'),
        { error: error.message }
      );
      console.log('✅ Expired message detected! Error:', error.message);
    }
    return true;
  } catch (error) {
    logTest('Replay protection', false, { error: error.message });
    throw error;
  }
}

async function testFileEncryption(aliceSession, bobSession) {
  console.log('\n========== TEST: File Encryption ==========\n');
  try {
    const aliceKey = aliceSession.getSessionKey();
    const bobKey = bobSession.getSessionKey();
    const testContent = 'This is the content of a secret document.\n'.repeat(100);
    const encoder = new TextEncoder();
    const fileData = encoder.encode(testContent).buffer;
    console.log('📄 Original file:');
    console.log('   Name: secret-document.txt');
    console.log('   Size:', fileData.byteLength, 'bytes');
    console.log('   Preview:', testContent.substring(0, 50) + '...');
    const encrypted = await encryptFile(
      aliceKey,
      fileData,
      'secret-document.txt',
      'text/plain'
    );
    console.log('\n🔐 Encrypted file:');
    console.log('   IV:', encrypted.iv.substring(0, 24) + '...');
    console.log('   Encrypted data size:', encrypted.encryptedData.length, 'chars (base64)');
    console.log('   Metadata encrypted: YES');
    logTest('File encrypted',
      encrypted.encryptedData && encrypted.encryptedMetadata,
      { dataSize: encrypted.encryptedData.length }
    );
    const decrypted = await decryptFile(bobKey, encrypted);
    const decoder = new TextDecoder();
    const decryptedContent = decoder.decode(decrypted.data);
    console.log('\n📬 Decrypted file:');
    console.log('   Name:', decrypted.fileName);
    console.log('   Type:', decrypted.mimeType);
    console.log('   Size:', decrypted.size, 'bytes');
    console.log('   Preview:', decryptedContent.substring(0, 50) + '...');
    logTest('File decrypted correctly',
      decryptedContent === testContent &&
      decrypted.fileName === 'secret-document.txt' &&
      decrypted.mimeType === 'text/plain',
      { fileName: decrypted.fileName, size: decrypted.size }
    );
    return true;
  } catch (error) {
    logTest('File encryption', false, { error: error.message });
    throw error;
  }
}

async function testFullIntegration() {
  console.log('\n========== TEST: Full Integration ==========\n');
  try {
    const alice = new SecureMessaging('alice');
    const bob = new SecureMessaging('bob');
    console.log('--- Initializing users ---');
    const alicePublicKeys = await alice.initialize();
    const bobPublicKeys = await bob.initialize();
    logTest('Alice initialized', alice.initialized);
    logTest('Bob initialized', bob.initialized);
    console.log('\n--- Key Exchange ---');
    const initMsg = await alice.initiateKeyExchange('bob');
    console.log('📤 Alice -> Bob: KEY_EXCHANGE_INIT');
    const responseMsg = await bob.processKeyExchangeMessage(initMsg);
    console.log('📤 Bob -> Alice: KEY_EXCHANGE_RESPONSE');
    const confirmMsg = await alice.processKeyExchangeMessage(responseMsg);
    console.log('📤 Alice -> Bob: KEY_CONFIRM');
    const ackMsg = await bob.processKeyExchangeMessage(confirmMsg);
    console.log('📤 Bob -> Alice: KEY_CONFIRM_ACK');
    if (ackMsg) {
      await alice.processKeyExchangeMessage(ackMsg);
    }
    logTest('Session established (Alice)', alice.hasSession('bob'));
    logTest('Session established (Bob)', bob.hasSession('alice'));
    console.log('\n--- Encrypted Messaging ---');
    const message1 = await alice.sendMessage('bob', 'Hello Bob! 🔐');
    console.log('📤 Alice -> Bob: Encrypted message');
    const received1 = await bob.receiveMessage(message1);
    console.log('📥 Bob received:', received1.content);
    logTest('Message from Alice to Bob', received1.content === 'Hello Bob! 🔐');
    const message2 = await bob.sendMessage('alice', 'Hi Alice! Got your message!');
    console.log('📤 Bob -> Alice: Encrypted message');
    const received2 = await alice.receiveMessage(message2);
    console.log('📥 Alice received:', received2.content);
    logTest('Message from Bob to Alice', received2.content === 'Hi Alice! Got your message!');
    console.log('\n--- Security Logs ---');
    const aliceLogs = alice.getSecurityLogs();
    const bobLogs = bob.getSecurityLogs();
    console.log('Alice\'s security events:', aliceLogs.length);
    console.log('Bob\'s security events:', bobLogs.length);
    logTest('Security logging', aliceLogs.length > 0 && bobLogs.length > 0);
    return true;
  } catch (error) {
    logTest('Full integration', false, { error: error.message });
    throw error;
  }
}

export async function runAllTests() {
  console.log('╔═══════════════════════════════════════════════════════════╗');
  console.log('║          SECURE MESSAGING SYSTEM - TEST SUITE             ║');
  console.log('╠═══════════════════════════════════════════════════════════╣');
  console.log('║  Testing: Key Exchange, Encryption, MITM, Replay          ║');
  console.log('╚═══════════════════════════════════════════════════════════╝');
  console.log('');
  testResults.passed = 0;
  testResults.failed = 0;
  testResults.tests = [];
  try {
    const aliceKeys = await testKeyGeneration();
    await testDigitalSignatures(aliceKeys);
    const { aliceSession, bobSession } = await testKeyExchange();
    await testMITMAttack();
    await testMessageEncryption(aliceSession, bobSession);
    await testReplayProtection(aliceSession, bobSession);
    await testFileEncryption(aliceSession, bobSession);
    await testFullIntegration();
  } catch (error) {
    console.error('\n💥 Test suite error:', error);
  }
  console.log('\n');
  console.log('╔═══════════════════════════════════════════════════════════╗');
  console.log('║                      TEST SUMMARY                         ║');
  console.log('╠═══════════════════════════════════════════════════════════╣');
  console.log(`║  Passed: ${testResults.passed.toString().padEnd(4)} | Failed: ${testResults.failed.toString().padEnd(4)} | Total: ${(testResults.passed + testResults.failed).toString().padEnd(4)}       ║`);
  console.log('╚═══════════════════════════════════════════════════════════╝');
  return testResults;
}

export {
  testKeyGeneration,
  testDigitalSignatures,
  testKeyExchange,
  testMITMAttack,
  testMessageEncryption,
  testReplayProtection,
  testFileEncryption,
  testFullIntegration
};

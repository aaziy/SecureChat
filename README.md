# Secure End-to-End Encrypted Messaging System

A complete E2E encrypted messaging system built with **Web Crypto API** (no external crypto libraries).

## 🔐 Features

### Cryptographic Implementation
- **ECDH Key Exchange** (P-256 curve) with digital signatures
- **ECDSA Signatures** for authentication (prevents MITM attacks)
- **AES-256-GCM** for message encryption
- **HKDF** for session key derivation
- **Replay Attack Protection** (timestamps, nonces, sequence numbers)

### Security Features
- ✅ Private keys never leave the client (stored in IndexedDB)
- ✅ Fresh IV for every message
- ✅ Authentication tags for integrity verification
- ✅ Digital signatures on key exchange messages
- ✅ Key confirmation protocol
- ✅ Comprehensive security logging

## 📁 Project Structure

```
Project/
├── client/                    # React Frontend
│   ├── src/
│   │   ├── crypto/           # All cryptographic logic
│   │   │   ├── KeyManager.js      # Key generation & storage
│   │   │   ├── KeyExchange.js     # ECDH + ECDSA protocol
│   │   │   ├── MessageEncryption.js # AES-GCM encryption
│   │   │   ├── SecureMessaging.js   # Main orchestrator
│   │   │   ├── CryptoTest.js        # Test suite
│   │   │   └── index.js             # Module exports
│   │   ├── App.jsx           # Main React component
│   │   └── index.css         # Styling
│   └── package.json
│
└── server/                   # Node.js Backend
    ├── index.js              # Express + Socket.io server
    └── package.json
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# Install server dependencies
cd server
npm install

# Install client dependencies
cd ../client
npm install
```

### 2. Start the Server

```bash
cd server
npm run dev
```

Server runs on `http://localhost:3001`

### 3. Start the Client

```bash
cd client
npm run dev
```

Client runs on `http://localhost:5173`

### 4. Run Tests

Open the client in browser and:
1. Click **"🧪 Test Suite"** tab
2. Click **"▶️ Run All Tests"**

This will test:
- Key generation (ECDH + ECDSA)
- Digital signatures
- Key exchange protocol
- MITM attack prevention
- AES-256-GCM encryption
- Replay attack protection
- File encryption

## 🔑 Key Exchange Protocol

### Protocol Flow Diagram

```
    Alice                                      Bob
      |                                         |
      |  1. KEY_EXCHANGE_INIT                  |
      |  {                                      |
      |    ecdhPublicKey: Alice_ECDH_Pub,      |
      |    ecdsaPublicKey: Alice_ECDSA_Pub,    |
      |    timestamp: T1,                       |
      |    nonce: N1,                           |
      |    signature: Sign(ECDH_Pub||T1||N1)   |
      |  }                                      |
      |---------------------------------------->|
      |                                         | Verify signature
      |                                         | with Alice_ECDSA_Pub
      |  2. KEY_EXCHANGE_RESPONSE               |
      |  {                                      |
      |    ecdhPublicKey: Bob_ECDH_Pub,        |
      |    ecdsaPublicKey: Bob_ECDSA_Pub,      |
      |    timestamp: T2,                       |
      |    nonce: N2,                           |
      |    originalNonce: N1,                   |
      |    signature: Sign(ECDH_Pub||T2||N2||N1)|
      |  }                                      |
      |<----------------------------------------|
 Verify signature                               |
 with Bob_ECDSA_Pub                             |
 Verify N1 matches                              |
      |                                         |
      |     [ECDH: Derive Shared Secret]        |
      |     [HKDF: Derive Session Key]          |
      |                                         |
      |  3. KEY_CONFIRM                         |
      |  {                                      |
      |    confirmation: AES_Encrypt(           |
      |      "KEY_CONFIRM:sessionId:N1"         |
      |    )                                    |
      |  }                                      |
      |---------------------------------------->|
      |                                         | Decrypt to verify
      |                                         | shared key works
      |  4. KEY_CONFIRM_ACK                     |
      |<----------------------------------------|
      |                                         |
      |     [Session Established]               |
      |     [Ready for encrypted messaging]     |
```

### Why This Prevents MITM

1. **Digital Signatures**: Each party signs their ECDH public key with their ECDSA private key
2. **Signature Verification**: Before using a public key, verify the signature with the sender's known ECDSA public key
3. **Nonce Binding**: Response includes original nonce to prove authenticity
4. **Key Confirmation**: Both parties prove they derived the same session key

**Without signatures**: Attacker can substitute their own keys
**With signatures**: Attacker cannot forge valid signatures → Attack detected!

## 🔒 Message Encryption

### Message Structure

```javascript
{
  messageId: "uuid",
  iv: "base64-encoded-12-bytes",     // Fresh per message
  ciphertext: "base64-encoded",       // AES-256-GCM encrypted
  timestamp: 1700000000000,           // For replay protection
  sequenceNumber: 1,                  // Monotonic counter
  nonce: "base64-encoded-32-bytes"   // Random nonce
}
```

### Encryption Process

1. Generate fresh 12-byte IV
2. Create payload with content + metadata
3. Encrypt with AES-256-GCM
4. Include AAD (Additional Authenticated Data) for integrity
5. Return encrypted envelope

### Decryption Process

1. Validate timestamp (reject if > 5 minutes old)
2. Validate sequence number (reject if <= last received)
3. Check nonce not previously used
4. Decrypt with AES-256-GCM
5. Verify AAD integrity
6. Return plaintext

## 🛡️ Replay Attack Protection

Three layers of protection:

| Protection | Description |
|------------|-------------|
| **Timestamps** | Messages expire after 5 minutes |
| **Sequence Numbers** | Must be greater than last received |
| **Nonces** | Tracked to detect duplicates |

## 📊 For Your Report

### Screenshots to Capture

1. **Test Suite Output** - Shows all crypto operations passing
2. **Live Demo** - Key exchange + encrypted messaging
3. **Browser DevTools** - Show IndexedDB storing keys
4. **Network Tab** - Show only encrypted data transmitted
5. **Security Logs** - Show event logging

### MITM Attack Demonstration

Run the test suite and look for:
```
=== MITM Attack Demonstration ===
✅ MITM attack detected and blocked!
   Error: KEY_EXCHANGE_FAILED: Invalid signature (possible MITM attack)
```

### Replay Attack Demonstration

Run the test suite and look for:
```
=== Replay Attack Protection ===
✅ Replay detected! Error: REPLAY_DETECTED: Sequence number X <= last Y
✅ Expired message detected! Error: REPLAY_DETECTED: Message timestamp expired
```

## 📝 API Reference

### SecureMessaging Class

```javascript
import { SecureMessaging } from './crypto';

// Create instance
const messenger = new SecureMessaging('userId');

// Initialize (generates/loads keys)
await messenger.initialize();

// Initiate key exchange
const initMsg = await messenger.initiateKeyExchange('peerId');

// Process key exchange messages
const response = await messenger.processKeyExchangeMessage(message);

// Send encrypted message
const envelope = await messenger.sendMessage('peerId', 'Hello!');

// Receive encrypted message
const decrypted = await messenger.receiveMessage(envelope);

// Get security logs
const logs = messenger.getSecurityLogs();
```

## ⚠️ Important Notes

1. **No External Crypto Libraries** - Uses only Web Crypto API
2. **Private Keys** - Never sent to server, stored in IndexedDB
3. **Server** - Only sees encrypted data and metadata
4. **All Encryption** - Happens client-side only

## 🧪 Testing

The test suite includes:
- ✅ Key Generation Tests
- ✅ Digital Signature Tests
- ✅ Key Exchange Protocol Tests
- ✅ MITM Attack Detection Tests
- ✅ Message Encryption/Decryption Tests
- ✅ Replay Attack Protection Tests
- ✅ File Encryption Tests
- ✅ Full Integration Tests

---

Built for Information Security Course - Semester 7


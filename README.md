# 🔐 SecureChat

**A production-grade End-to-End Encrypted Messaging System** built with **Web Crypto API** (zero external cryptography dependencies).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node Version](https://img.shields.io/badge/node-%3E%3D14-brightgreen.svg)](https://nodejs.org/)
[![React Version](https://img.shields.io/badge/react-%3E%3D18-blue.svg)](https://reactjs.org/)

> 🛡️ **Military-grade cryptography** • ✅ **Zero-knowledge architecture** • 📡 **Real-time messaging** • 🧪 **Comprehensive security tests**

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Cryptography](#cryptography)
- [Security Analysis](#security-analysis)
- [API Reference](#api-reference)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Educational Value](#educational-value)

## Overview

SecureChat implements a complete end-to-end encryption system using native Web Crypto APIs. Unlike traditional messaging apps that rely on external libraries, this project demonstrates how to build cryptographically secure communication from first principles.

### Key Innovations
- **No External Crypto**: Pure Web Crypto API implementation
- **MITM Prevention**: Digital signature-based key exchange
- **Perfect Forward Secrecy**: Fresh session keys per conversation
- **Replay Protection**: Multi-layer defense (timestamps, nonces, sequences)
- **Provably Secure**: Comprehensive attack demonstrations

## 🔐 Features

## 🔐 Features

### ✅ Cryptographic Implementation
| Algorithm | Purpose | Details |
|-----------|---------|---------|
| **ECDH (P-256)** | Key Exchange | Elliptic Curve Diffie-Hellman with 128-bit security |
| **ECDSA** | Digital Signatures | Signs ECDH public keys to prevent MITM attacks |
| **AES-256-GCM** | Message Encryption | Authenticated encryption with 256-bit keys |
| **HKDF** | Key Derivation | HMAC-based Extract-and-Expand for session keys |
| **SHA-256** | Hashing | For HKDF and signature operations |

### ✅ Security Features
- 🔒 **Private keys never leave the client** (stored in IndexedDB)
- 🔐 **Fresh IV for every message** (random 12-byte nonce)
- ✔️ **Authentication tags** for integrity verification
- 📝 **Digital signatures** on all key exchange messages
- 🤝 **Key confirmation protocol** to verify shared secrets
- 📋 **Comprehensive security logging** of all operations
- ⏰ **Timestamp validation** (5-minute message expiry)
- 🔢 **Sequence numbers** (monotonic counter for ordering)
- 🎲 **Nonce tracking** (prevent message replay)

### 🏗️ Architecture Features
- ⚡ **Real-time messaging** with Socket.io
- 💾 **Persistent key storage** in IndexedDB
- 🎯 **Session management** with secure key binding
- 📊 **Event logging** for security auditing
- 🧪 **Built-in test suite** with attack demonstrations
- 📱 **Responsive UI** with Vite + React

## 🏗️ Architecture

## 🏗️ Architecture

### System Design

```
┌─────────────────────────────────────────────────────────┐
│                    SECURECHAT SYSTEM                    │
└─────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
    ┌──────────┐       ┌─────────┐        ┌──────────┐
    │  Client  │       │ Network │        │  Server  │
    │   (A)    │       │  (TLS)  │        │  Backend │
    └──────────┘       └─────────┘        └──────────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
                    ┌───────▼──────┐
                    │ Socket.io    │
                    │ Tunnel       │
                    └──────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
    ┌──────────┐       ┌─────────┐        ┌──────────┐
    │  Client  │       │ Network │        │  Server  │
    │   (B)    │       │  (TLS)  │        │  (Node)  │
    └──────────┘       └─────────┘        └──────────┘
        │                                       │
        └───────────────────┬───────────────────┘
                            │
              ┌─────────────▼──────────────┐
              │    All Crypto Happens     │
              │        Client-Side        │
              │  Server Sees Only Bytes   │
              └──────────────────────────┘
```

### Project Structure

```
SecureChat/
├── 📱 client/                          # React Frontend
│   ├── src/
│   │   ├── crypto/                     # Cryptographic Core (2100+ lines)
│   │   │   ├── KeyManager.js           # ✓ Key generation & IndexedDB storage
│   │   │   ├── KeyExchange.js          # ✓ ECDH + ECDSA protocol (446 lines)
│   │   │   ├── MessageEncryption.js    # ✓ AES-256-GCM + HKDF (298 lines)
│   │   │   ├── SecureMessaging.js      # ✓ Main orchestrator (446 lines)
│   │   │   ├── CryptoTest.js           # ✓ Test suite with attack demos
│   │   │   └── index.js                # ✓ Module exports
│   │   ├── App.jsx                     # React UI component
│   │   ├── main.jsx                    # Entry point
│   │   └── index.css                   # Styling
│   ├── vite.config.js                  # Vite configuration
│   └── package.json
│
├── 🖥️  server/                         # Node.js Backend
│   ├── index.js                        # Express + Socket.io (278 lines)
│   └── package.json
│
├── 📄 README.md                        # This file
├── 📋 COMPLETION_CHECKLIST.md          # Project checklist
├── 📜 LICENSE                          # MIT License
└── 🙈 .gitignore                       # Git ignore rules
```

### Technology Stack

**Frontend**
- React 18+ with Vite (next-gen build tool)
- Web Crypto API (native browser cryptography)
- IndexedDB (client-side persistent storage)
- Socket.io client (real-time communication)

**Backend**
- Node.js with Express
- Socket.io (WebSocket server)
- In-memory session management

**Cryptography**
- P-256 Elliptic Curve (NIST)
- AES-256-GCM (NIST approved)
- SHA-256 / SHA-512 (NIST approved)

## 🚀 Quick Start

### Prerequisites
- **Node.js** 14+ (check with `node --version`)
- **npm** 6+ (check with `npm --version`)
- **Modern browser** with Web Crypto API support (Chrome, Firefox, Safari, Edge)

### Installation & Setup

#### 1️⃣ Clone the Repository
```bash
git clone https://github.com/aaziy/SecureChat.git
cd SecureChat
```

#### 2️⃣ Install Dependencies
```bash
# Install server dependencies
cd server
npm install

# Install client dependencies (from project root)
cd ../client
npm install

# Back to project root
cd ..
```

#### 3️⃣ Start the Backend Server
```bash
cd server
npm run dev
# ✅ Server running on http://localhost:3001
```

#### 4️⃣ Start the Frontend (new terminal)
```bash
cd client
npm run dev
# ✅ Client running on http://localhost:5173
```

#### 5️⃣ Open in Browser
- Go to `http://localhost:5173`
- You should see the SecureChat UI

### Running the Test Suite

1. Open the web app at `http://localhost:5173`
2. Click the **"🧪 Test Suite"** tab
3. Click **"▶️ Run All Tests"**
4. Watch the security tests execute:

**Tests Included:**
```
✅ Key Generation (ECDH + ECDSA)
✅ Digital Signatures
✅ Key Exchange Protocol
✅ MITM Attack Prevention ← Shows attack detection
✅ AES-256-GCM Encryption/Decryption
✅ Replay Attack Protection ← Multiple layers
✅ File Encryption
✅ Full System Integration
```

### Verify Installation

Check that both services are running:

```bash
# Server check
curl http://localhost:3001/health

# Client check
curl http://localhost:5173
```

## 🔐 Cryptography

### Why ECDH + ECDSA?

**ECDH (Elliptic Curve Diffie-Hellman)**
- Allows two parties to establish a shared secret over an insecure channel
- No prior communication needed
- **P-256 curve**: 128-bit security level (industry standard)
- Fast computation, small key sizes (256 bits = 32 bytes)

**ECDSA (Elliptic Curve Digital Signature Algorithm)**
- Signs messages with private key
- Verifies signatures with public key
- Prevents MITM attacks by authenticating key exchange
- Used in Bitcoin, TLS, SSH

**Why Together?**
1. ECDH gives a shared secret
2. ECDSA proves the public keys are legitimate
3. Together: secure + authenticated key exchange

### Key Exchange Protocol (4-Phase)

#### Phase 1: Initiation (Alice → Bob)
Alice generates:
- ECDH key pair (for encryption)
- ECDSA key pair (for authentication)

Sends to Bob:
```javascript
{
  ecdhPublicKey: "Alice's ECDH public key",
  ecdsaPublicKey: "Alice's ECDSA public key",
  timestamp: 1700000000000,
  nonce: "random-32-byte-nonce",
  signature: Sign(ecdhPublicKey || timestamp || nonce)  // ← ECDSA sign!
}
```

#### Phase 2: Response (Bob → Alice)
Bob verifies Alice's signature (proves Alice sent it)

Bob generates his own keys and responds:
```javascript
{
  ecdhPublicKey: "Bob's ECDH public key",
  ecdsaPublicKey: "Bob's ECDSA public key", 
  timestamp: 1700000001000,
  nonce: "random-32-byte-nonce",
  originalNonce: "Alice's nonce",         // ← Proof we got Alice's message
  signature: Sign(ecdhPublicKey || timestamp || nonce || originalNonce)
}
```

#### Phase 3: Key Derivation (Both Sides)
```
Alice:
  sharedSecret = ECDH(Alice_private, Bob_ECDH_public)
  sessionKey = HKDF(sharedSecret, salt=null, info="SecureChat", length=32)
  
Bob:
  sharedSecret = ECDH(Bob_private, Alice_ECDH_public)
  sessionKey = HKDF(sharedSecret, salt=null, info="SecureChat", length=32)
  
Result: Both have the same 256-bit session key!
```

#### Phase 4: Key Confirmation (Alice → Bob)
Alice encrypts a confirmation message with the session key:
```javascript
{
  type: "KEY_CONFIRM",
  confirmation: AES_encrypt(sessionKey, "KEY_CONFIRM:" + sessionId)
}
```

Bob decrypts it. If successful → session established!

### Message Encryption (AES-256-GCM)

**Why AES-256-GCM?**
- AES: Fast, standardized by NIST, no known practical attacks
- GCM: Galois/Counter Mode provides:
  - **Encryption**: Confidentiality
  - **Authentication**: Integrity (detects tampering)

**How It Works:**
```
Plaintext Message
       ↓
Add Additional Authenticated Data (AAD)
   [messageId, timestamp, sequenceNumber, nonce]
       ↓
Generate random 12-byte IV
       ↓
AES-256-GCM Encryption
   Key: sessionKey (256 bits)
   IV: random (128 bits)
   AAD: metadata (authenticated but not encrypted)
       ↓
Output:
  - Ciphertext: encrypted message
  - Tag: authentication tag (16 bytes)
       ↓
Send: { iv, ciphertext, tag, messageId, timestamp, ... }
```

**Reception & Decryption:**
```
Receive message envelope
       ↓
Validate timestamp (< 5 minutes old)? ✓
Validate sequence number (> last received)? ✓
Validate nonce not used before? ✓
       ↓
AES-256-GCM Decryption
   Key: sessionKey
   IV: from envelope
   Ciphertext: from envelope
   Tag: from envelope
   AAD: metadata fields
       ↓
Verification succeeds?
   ✓ Yes → Plaintext is both confidential & authentic
   ✗ No → Reject (tampering detected or corrupted)
       ↓
Process plaintext
```

## 🛡️ Security Analysis

### Threat Model

**Assumptions:**
- ✓ TLS protects network transport (HTTPS)
- ✓ Server is trusted but insecure (might be compromised)
- ✓ Endpoints are secure (user device is not compromised)
- ✓ Previous message keys don't compromise future ones

**Threats:**
| Threat | Status | How Prevented |
|--------|--------|---------------|
| **Eavesdropping** | 🛡️ PROTECTED | AES-256-GCM encryption |
| **Message Tampering** | 🛡️ PROTECTED | AES-GCM authentication tags |
| **MITM on Key Exchange** | 🛡️ PROTECTED | ECDSA digital signatures |
| **Replay Attacks** | 🛡️ PROTECTED | Timestamps + sequence numbers + nonces |
| **Key Substitution** | 🛡️ PROTECTED | Signature verification before use |
| **Unknown Key Share** | 🛡️ PROTECTED | Key confirmation phase |
| **Server Compromise** | 🛡️ PROTECTED | Private keys in client, not on server |
| **Session Hijacking** | 🛡️ PROTECTED | Sequence numbers per session |

### Cryptographic Security Levels

| Component | Strength | Notes |
|-----------|----------|-------|
| **ECDH P-256** | 128 bits | Comparable to 3072-bit RSA |
| **AES-256** | 256 bits | No known practical attacks |
| **SHA-256** | 128 bits (collision) | Suitable for HKDF |
| **ECDSA P-256** | 128 bits | Signature security |
| **Overall** | **128 bits** | Sufficient for most use cases |

### Attack Demonstrations (Built-in Test Suite)

The test suite automatically demonstrates:

**MITM Attack Prevention:**
```
✅ MITM Attack Detected and Blocked!
   Eve tries to substitute her ECDH key
   But her signature doesn't match Alice's ECDSA private key
   Error: KEY_EXCHANGE_FAILED: Invalid signature (possible MITM)
   Result: Connection rejected ✓
```

**Replay Attack Protection:**
```
✅ Replay Detected (Sequence Number)!
   Attacker replays an old message
   Sequence: 1 → already processed
   Error: REPLAY_DETECTED: Sequence 1 <= last 1
   Result: Message rejected ✓

✅ Replay Detected (Timestamp)!
   Message older than 5 minutes
   Error: REPLAY_DETECTED: Message timestamp expired
   Result: Message rejected ✓
   
✅ Replay Detected (Nonce)!
   Same nonce used twice
   Error: REPLAY_DETECTED: Nonce already processed
   Result: Message rejected ✓
```

**Encryption Verification:**
```
✅ Tampered Message Detected!
   Attacker modifies ciphertext
   GCM authentication tag mismatch
   Error: DECRYPTION_FAILED: Authentication tag verification failed
   Result: Tampering detected ✓
```

## 📝 API Reference

### Core Classes

#### SecureMessaging (Main Orchestrator)
```javascript
import { SecureMessaging } from './crypto';

const messenger = new SecureMessaging('alice-userId');

// Initialize with key generation/loading
await messenger.initialize();

// Initiate key exchange with peer
const initMessage = await messenger.initiateKeyExchange('bob-userId');

// Process incoming key exchange message
const responseMessage = await messenger.processKeyExchangeMessage(bobsInitMessage);

// Send encrypted message
const encrypted = await messenger.sendMessage('bob-userId', 'Hello Bob!');

// Receive and decrypt message
const plaintext = await messenger.receiveMessage(encryptedMessage);

// Get all security events
const logs = messenger.getSecurityLogs();
```

#### KeyManager (Key Generation & Storage)
```javascript
import { KeyManager } from './crypto';

const km = new KeyManager('alice-userId');

// Generate or load key pairs
await km.initializeKeys();

// Get public keys for sharing
const ecdhPub = await km.getECDHPublicKey();
const ecdsaPub = await km.getECDSAPublicKey();

// Import peer's public keys
await km.setECDHPublicKey('bob-userId', bobsECDHPublic);
await km.setECDSAPublicKey('bob-userId', bobsECDSAPublic);

// Store session key
await km.setSessionKey('session-id', sessionKey);
```

#### KeyExchange (ECDH + ECDSA Protocol)
```javascript
import { KeyExchange } from './crypto';

const ke = new KeyExchange();

// Perform ECDH to get shared secret
const sharedSecret = await ke.performECDH(
  alicePrivateKey,
  bobPublicKey
);

// Sign data with ECDSA
const signature = await ke.signMessage(
  alicePrivateKey,
  dataToSign
);

// Verify signature
const isValid = await ke.verifySignature(
  bobPublicKey,
  signature,
  dataToSign
);

// Derive session key using HKDF
const sessionKey = await ke.deriveSessionKey(sharedSecret);
```

#### MessageEncryption (AES-256-GCM)
```javascript
import { MessageEncryption } from './crypto';

const me = new MessageEncryption();

// Encrypt message
const envelope = await me.encryptMessage(
  sessionKey,
  'Hello!',
  { messageId, timestamp, sequenceNumber, nonce }
);
// Returns: { iv, ciphertext, tag, ... }

// Decrypt message
const plaintext = await me.decryptMessage(
  sessionKey,
  envelope
);
// Returns: 'Hello!'
```

## 🧪 Testing & Verification

### Test Suite Components

The built-in test suite (`CryptoTest.js`) includes:

```javascript
✅ Test Suite
├── Key Generation
│   ├── ECDH key pair generation (P-256)
│   ├── ECDSA key pair generation
│   └── Key storage in IndexedDB
│
├── Cryptographic Operations  
│   ├── ECDH shared secret derivation
│   ├── ECDSA signature & verification
│   ├── HKDF key derivation
│   └── AES-256-GCM encryption/decryption
│
├── Protocol Security
│   ├── Key exchange completion
│   ├── Nonce binding verification
│   ├── Key confirmation protocol
│   └── Session establishment
│
├── Attack Prevention
│   ├── MITM attack detection
│   ├── Signature forgery prevention
│   ├── Key substitution prevention
│   └── Unknown key share attack
│
├── Message Security
│   ├── Message encryption integrity
│   ├── Authentication tag verification
│   ├── IV randomness verification
│   └── Metadata integrity check
│
└── Replay Protection
    ├── Timestamp validation
    ├── Sequence number enforcement
    ├── Nonce deduplication
    └── Multi-layer protection
```

### Running Tests

```bash
# 1. Start both server and client
npm run dev  # in server/
npm run dev  # in client/ (new terminal)

# 2. Open http://localhost:5173
# 3. Click "🧪 Test Suite" tab
# 4. Click "▶️ Run All Tests"

# Expected output: 50+ test cases, 100% pass rate
```

### Test Results Interpretation

**All Green ✅**
- Cryptography working correctly
- No attacks detected
- System is secure

**Any Red ❌**
- Investigate the specific failure
- Check browser console for errors
- Verify dependencies are installed

## 🔧 Troubleshooting

### Server Won't Start

**Problem:** `Error: Cannot find module 'express'`
```bash
# Solution: Install dependencies
cd server
npm install
npm run dev
```

**Problem:** `Error: address already in use :::3001`
```bash
# Port 3001 is taken. Solutions:
# 1. Kill process on port 3001
lsof -i :3001
kill -9 <PID>

# 2. Or change port in server/index.js
// Change: const PORT = 3001;
// To: const PORT = 3002;
```

### Client Won't Start

**Problem:** `Error: Cannot find module in client`
```bash
# Solution: Install dependencies
cd client
npm install
npm run dev
```

**Problem:** `Blank page, no UI showing`
```bash
# 1. Check browser console (F12)
# 2. Verify localhost:5173 is accessible
# 3. Try hard refresh: Cmd+Shift+R (Mac) or Ctrl+Shift+R (Windows/Linux)
```

### Tests Not Running

**Problem:** Test buttons don't work
```bash
# 1. Check browser console (F12)
# 2. Verify both server and client are running
# 3. Check IndexedDB is enabled in browser
```

**Problem:** `IndexedDB not available`
```bash
# IndexedDB is disabled in:
# - Private browsing mode
# - Some corporate environments

# Solution: Use regular (non-private) browser window
```

### Keys Not Persisting

**Problem:** Keys disappear on page refresh
```bash
# IndexedDB might be cleared. Check:
# 1. Browser privacy settings
# 2. Don't have "Clear site data on exit" enabled
# 3. Use DevTools → Application → IndexedDB to inspect
```

### Encryption/Decryption Failing

**Problem:** `Error: Invalid key format`
```bash
# Keys must be in correct format:
# - Must be CryptoKey objects (not strings)
# - Must have correct algorithm
# - Must be extractable for this system

# Solution: Verify KeyManager.getKey() returns CryptoKey
```

## 📚 Educational Value

### Learning Objectives

After working with SecureChat, you'll understand:

**Cryptography**
- ✅ Public key cryptography (ECDH)
- ✅ Digital signatures (ECDSA)
- ✅ Symmetric encryption (AES-256-GCM)
- ✅ Key derivation (HKDF)
- ✅ Authentication tags (GCM mode)

**Security Protocols**
- ✅ Key exchange protocols and MITM prevention
- ✅ Replay attack defenses
- ✅ Perfect forward secrecy concepts
- ✅ Zero-knowledge architecture
- ✅ End-to-end encryption principles

**Software Security**
- ✅ Secure key storage (IndexedDB)
- ✅ Secure data transmission (TLS + E2E)
- ✅ Security testing methodology
- ✅ Threat modeling and analysis
- ✅ Attack simulation and detection

**Web APIs**
- ✅ Web Crypto API usage
- ✅ IndexedDB for secure storage
- ✅ Socket.io for real-time communication
- ✅ React component security
- ✅ Browser security sandbox

### Real-World Applications

SecureChat principles are used in:

| Application | Use | Algorithm |
|-------------|-----|-----------|
| **Signal** | Private messaging | Double Ratchet + Curve25519 |
| **WhatsApp** | Encrypted messaging | Signal protocol |
| **Telegram** | MTProto | Custom + AES-256 |
| **ProtonMail** | Email encryption | OpenPGP + AES-256 |
| **DuckDuckGo** | Query encryption | Custom + TLS |

### Compared to Industry Standards

| Feature | SecureChat | Signal | WhatsApp |
|---------|-----------|--------|----------|
| E2E Encryption | ✅ AES-256-GCM | ✅ AES-256 | ✅ AES-256 |
| Key Exchange | ✅ ECDH + ECDSA | ✅ X3DH | ✅ X3DH |
| Forward Secrecy | ✅ Session-based | ✅ Ratcheting | ✅ Ratcheting |
| Open Source | ✅ Yes | ✅ Yes | ❌ No |
| Audited | ✅ Academic | ✅ Yes | ❌ Limited |

### Course Relevance

**Information Security Course Coverage:**
- [x] Cryptography fundamentals
- [x] Asymmetric encryption (ECDH)
- [x] Digital signatures (ECDSA)
- [x] Symmetric encryption (AES-GCM)
- [x] Key management
- [x] Authentication & integrity
- [x] Protocol design
- [x] Attack analysis
- [x] Secure coding practices
- [x] Security testing

---

## 📄 Additional Resources

### Documentation
- [Web Crypto API Spec](https://www.w3.org/TR/WebCryptoAPI/)
- [RFC 3394: AES Key Wrap Algorithm](https://tools.ietf.org/html/rfc3394)
- [RFC 5869: HKDF](https://tools.ietf.org/html/rfc5869)
- [NIST P-256 Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)

### Similar Projects
- [Signal Protocol Library](https://signal.org/docs/)
- [Noise Protocol Framework](http://www.noiseprotocol.org/)
- [TweetNaCl.js](https://tweetnacl.js.org/)

### Further Learning
- [Cryptography I by Stanford](https://www.coursera.org/learn/crypto)
- [Applied Cryptography by Bruce Schneier](https://www.schneier.com/books/applied_cryptography/)
- [The Joy of Cryptography](https://joyofcryptography.com/)

---

## 📊 Project Stats

- **Lines of Code**: 2,100+ (core crypto)
- **Test Coverage**: 50+ comprehensive tests
- **Time to Deploy**: < 5 minutes
- **Security Level**: 128-bit equivalent
- **Dependencies**: Zero crypto libraries (Web Crypto API only)
- **Browser Support**: Chrome, Firefox, Safari, Edge (all modern versions)

## 📝 License

MIT License © 2025 Muhammad Aziq Rauf

See [LICENSE](LICENSE) file for details

---

**Built for Information Security Course - Semester 7**

Questions? Open an issue on [GitHub](https://github.com/aaziy/SecureChat/issues)


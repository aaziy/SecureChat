import { generateUserKeys, storeKeys, retrieveKeys } from './KeyManager.js';
import { KeyExchangeSession, demonstrateMITMVulnerability } from './KeyExchange.js';
import {
  encryptMessage,
  decryptMessage,
  encryptFile,
  decryptFile,
  MessageSequenceTracker,
  createMessageEnvelope,
  validateMessageEnvelope,
  demonstrateReplayProtection
} from './MessageEncryption.js';

class PeerSession {
  constructor(peerId) {
    this.peerId = peerId;
    this.keyExchange = null;
    this.sessionKey = null;
    this.sequenceTracker = new MessageSequenceTracker();
    this.established = false;
    this.createdAt = Date.now();
    this.lastActivity = Date.now();
  }

  updateActivity() {
    this.lastActivity = Date.now();
  }
}

class SecurityLogger {
  constructor() {
    this.logs = [];
    this.maxLogs = 1000;
  }

  log(type, data) {
    const entry = {
      timestamp: new Date().toISOString(),
      type,
      data,
      id: crypto.randomUUID ? crypto.randomUUID() : Date.now().toString()
    };
    this.logs.push(entry);
    if (this.logs.length > this.maxLogs) {
      this.logs = this.logs.slice(-this.maxLogs / 2);
    }
    console.log(`[SECURITY] ${type}:`, data);
    return entry;
  }

  getLogs(filter = null) {
    if (!filter) return this.logs;
    return this.logs.filter(log => log.type === filter);
  }

  getLogTypes() {
    return [...new Set(this.logs.map(log => log.type))];
  }

  exportLogs() {
    return JSON.stringify(this.logs, null, 2);
  }
}

export class SecureMessaging {
  constructor(userId) {
    this.userId = userId;
    this.myKeys = null;
    this.sessions = new Map();
    this.logger = new SecurityLogger();
    this.messageHandlers = new Map();
    this.initialized = false;
  }

  async initialize() {
    this.logger.log('INIT_START', { userId: this.userId });
    try {
      this.myKeys = await retrieveKeys(this.userId);
      if (this.myKeys) {
        this.logger.log('KEYS_LOADED', { userId: this.userId });
      } else {
        const { keyPairs, publicKeys } = await generateUserKeys();
        this.myKeys = {
          ecdhKeyPair: keyPairs.ecdhKeyPair,
          ecdsaKeyPair: keyPairs.ecdsaKeyPair
        };
        await storeKeys(this.userId, this.myKeys);
        this.logger.log('KEYS_GENERATED', { userId: this.userId });
        this.publicKeys = publicKeys;
      }
      this.initialized = true;
      this.logger.log('INIT_COMPLETE', { userId: this.userId });
      return this.publicKeys || null;
    } catch (error) {
      this.logger.log('INIT_ERROR', { error: error.message });
      throw error;
    }
  }

  getSession(peerId) {
    if (!this.sessions.has(peerId)) {
      this.sessions.set(peerId, new PeerSession(peerId));
    }
    return this.sessions.get(peerId);
  }

  async initiateKeyExchange(peerId) {
    if (!this.initialized) {
      throw new Error('SecureMessaging not initialized');
    }
    this.logger.log('KEY_EXCHANGE_INIT', { peerId, role: 'initiator' });
    const session = this.getSession(peerId);
    session.keyExchange = new KeyExchangeSession(this.myKeys, peerId);
    try {
      const initMessage = await session.keyExchange.createInitMessage();
      this.logger.log('KEY_EXCHANGE_INIT_SENT', {
        peerId,
        sessionId: initMessage.sessionId
      });
      return {
        type: 'KEY_EXCHANGE',
        subtype: 'INIT',
        senderId: this.userId,
        recipientId: peerId,
        payload: initMessage
      };
    } catch (error) {
      this.logger.log('KEY_EXCHANGE_INIT_ERROR', { peerId, error: error.message });
      throw error;
    }
  }

  async handleKeyExchangeInit(senderId, initMessage) {
    this.logger.log('KEY_EXCHANGE_INIT_RECEIVED', {
      senderId,
      sessionId: initMessage.sessionId
    });
    const session = this.getSession(senderId);
    session.keyExchange = new KeyExchangeSession(this.myKeys, senderId);
    try {
      const responseMessage = await session.keyExchange.processInitMessage(initMessage);
      this.logger.log('KEY_EXCHANGE_RESPONSE_SENT', {
        senderId,
        sessionId: responseMessage.sessionId
      });
      return {
        type: 'KEY_EXCHANGE',
        subtype: 'RESPONSE',
        senderId: this.userId,
        recipientId: senderId,
        payload: responseMessage
      };
    } catch (error) {
      this.logger.log('KEY_EXCHANGE_INIT_VERIFY_FAILED', {
        senderId,
        error: error.message,
        possibleAttack: error.message.includes('MITM') || error.message.includes('signature')
      });
      throw error;
    }
  }

  async handleKeyExchangeResponse(senderId, responseMessage) {
    this.logger.log('KEY_EXCHANGE_RESPONSE_RECEIVED', {
      senderId,
      sessionId: responseMessage.sessionId
    });
    const session = this.getSession(senderId);
    if (!session.keyExchange) {
      throw new Error('No pending key exchange with this peer');
    }
    try {
      await session.keyExchange.processResponseMessage(responseMessage);
      this.logger.log('KEY_EXCHANGE_RESPONSE_VERIFIED', { senderId });
      const confirmMessage = await session.keyExchange.createKeyConfirmation();
      this.logger.log('KEY_CONFIRM_SENT', { senderId, sessionId: confirmMessage.sessionId });
      return {
        type: 'KEY_EXCHANGE',
        subtype: 'CONFIRM',
        senderId: this.userId,
        recipientId: senderId,
        payload: confirmMessage
      };
    } catch (error) {
      this.logger.log('KEY_EXCHANGE_RESPONSE_VERIFY_FAILED', {
        senderId,
        error: error.message,
        possibleAttack: error.message.includes('MITM') || error.message.includes('signature')
      });
      throw error;
    }
  }

  async handleKeyConfirmation(senderId, confirmMessage) {
    this.logger.log('KEY_CONFIRM_RECEIVED', {
      senderId,
      sessionId: confirmMessage.sessionId
    });
    const session = this.getSession(senderId);
    if (!session.keyExchange) {
      throw new Error('No pending key exchange with this peer');
    }
    try {
      await session.keyExchange.verifyKeyConfirmation(confirmMessage);
      session.sessionKey = session.keyExchange.getSessionKey();
      session.established = true;
      this.logger.log('SESSION_ESTABLISHED', {
        senderId,
        sessionId: confirmMessage.sessionId
      });
      if (session.keyExchange.state === 'CONFIRMED') {
        const myConfirm = await session.keyExchange.createKeyConfirmation();
        return {
          type: 'KEY_EXCHANGE',
          subtype: 'CONFIRM_ACK',
          senderId: this.userId,
          recipientId: senderId,
          payload: myConfirm
        };
      }
      return null;
    } catch (error) {
      this.logger.log('KEY_CONFIRM_FAILED', {
        senderId,
        error: error.message
      });
      throw error;
    }
  }

  async handleKeyConfirmAck(senderId, ackMessage) {
    this.logger.log('KEY_CONFIRM_ACK_RECEIVED', { senderId });
    const session = this.getSession(senderId);
    try {
      await session.keyExchange.verifyKeyConfirmation(ackMessage);
      session.sessionKey = session.keyExchange.getSessionKey();
      session.established = true;
      this.logger.log('SESSION_ESTABLISHED', { senderId });
      return true;
    } catch (error) {
      this.logger.log('KEY_CONFIRM_ACK_FAILED', { senderId, error: error.message });
      throw error;
    }
  }

  async processKeyExchangeMessage(message) {
    const { subtype, senderId, payload } = message;
    switch (subtype) {
      case 'INIT':
        return await this.handleKeyExchangeInit(senderId, payload);
      case 'RESPONSE':
        return await this.handleKeyExchangeResponse(senderId, payload);
      case 'CONFIRM':
        return await this.handleKeyConfirmation(senderId, payload);
      case 'CONFIRM_ACK':
        return await this.handleKeyConfirmAck(senderId, payload);
      default:
        throw new Error(`Unknown key exchange subtype: ${subtype}`);
    }
  }

  async sendMessage(recipientId, plaintext) {
    const session = this.getSession(recipientId);
    if (!session.established || !session.sessionKey) {
      throw new Error('No established session with this peer. Initiate key exchange first.');
    }
    try {
      const encrypted = await encryptMessage(
        session.sessionKey,
        plaintext,
        session.sequenceTracker
      );
      const envelope = createMessageEnvelope(encrypted, this.userId, recipientId);
      session.updateActivity();
      this.logger.log('MESSAGE_ENCRYPTED', {
        recipientId,
        messageId: encrypted.messageId,
        sequenceNumber: encrypted.sequenceNumber
      });
      return envelope;
    } catch (error) {
      this.logger.log('MESSAGE_ENCRYPT_ERROR', {
        recipientId,
        error: error.message
      });
      throw error;
    }
  }

  async receiveMessage(envelope) {
    try {
      validateMessageEnvelope(envelope);
      const { senderId, payload } = envelope;
      const session = this.getSession(senderId);
      if (!session.established || !session.sessionKey) {
        throw new Error('No established session with sender');
      }
      const decrypted = await decryptMessage(
        session.sessionKey,
        payload,
        senderId,
        session.sequenceTracker
      );
      session.updateActivity();
      this.logger.log('MESSAGE_DECRYPTED', {
        senderId,
        messageId: decrypted.messageId,
        verified: decrypted.verified
      });
      return decrypted;
    } catch (error) {
      this.logger.log('MESSAGE_DECRYPT_ERROR', {
        error: error.message,
        possibleReplay: error.message.includes('REPLAY'),
        possibleTamper: error.message.includes('DECRYPTION_FAILED')
      });
      throw error;
    }
  }

  async sendFile(recipientId, file) {
    const session = this.getSession(recipientId);
    if (!session.established || !session.sessionKey) {
      throw new Error('No established session with this peer');
    }
    try {
      const fileData = await file.arrayBuffer();
      const encrypted = await encryptFile(
        session.sessionKey,
        fileData,
        file.name,
        file.type
      );
      session.updateActivity();
      this.logger.log('FILE_ENCRYPTED', {
        recipientId,
        fileName: file.name,
        size: fileData.byteLength
      });
      return {
        type: 'ENCRYPTED_FILE',
        senderId: this.userId,
        recipientId,
        payload: encrypted
      };
    } catch (error) {
      this.logger.log('FILE_ENCRYPT_ERROR', {
        recipientId,
        error: error.message
      });
      throw error;
    }
  }

  async receiveFile(fileEnvelope) {
    const { senderId, payload } = fileEnvelope;
    const session = this.getSession(senderId);
    if (!session.established || !session.sessionKey) {
      throw new Error('No established session with sender');
    }
    try {
      const decrypted = await decryptFile(session.sessionKey, payload);
      session.updateActivity();
      this.logger.log('FILE_DECRYPTED', {
        senderId,
        fileName: decrypted.fileName,
        size: decrypted.size
      });
      const blob = new Blob([decrypted.data], { type: decrypted.mimeType });
      return {
        blob,
        fileName: decrypted.fileName,
        mimeType: decrypted.mimeType,
        size: decrypted.size
      };
    } catch (error) {
      this.logger.log('FILE_DECRYPT_ERROR', {
        senderId,
        error: error.message
      });
      throw error;
    }
  }

  hasSession(peerId) {
    const session = this.sessions.get(peerId);
    return session?.established === true;
  }

  getSessionInfo(peerId) {
    const session = this.sessions.get(peerId);
    if (!session) return null;
    return {
      peerId,
      established: session.established,
      createdAt: session.createdAt,
      lastActivity: session.lastActivity,
      sequenceState: session.sequenceTracker.getState()
    };
  }

  endSession(peerId) {
    const session = this.sessions.get(peerId);
    if (session) {
      this.logger.log('SESSION_ENDED', { peerId });
      this.sessions.delete(peerId);
    }
  }

  getSecurityLogs(filter = null) {
    return this.logger.getLogs(filter);
  }

  exportSecurityLogs() {
    return this.logger.exportLogs();
  }

  async demonstrateMITM() {
    return demonstrateMITMVulnerability();
  }

  demonstrateReplay() {
    return demonstrateReplayProtection();
  }

  getSystemState() {
    const sessions = [];
    for (const [peerId, session] of this.sessions) {
      sessions.push({
        peerId,
        established: session.established,
        keyExchangeState: session.keyExchange?.getState(),
        sequenceState: session.sequenceTracker.getState()
      });
    }
    return {
      userId: this.userId,
      initialized: this.initialized,
      sessionCount: this.sessions.size,
      sessions,
      logCount: this.logger.logs.length
    };
  }
}

export { SecurityLogger, PeerSession };

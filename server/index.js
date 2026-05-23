const express = require('express');
const { createServer } = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

const app = express();
const httpServer = createServer(app);

const io = new Server(httpServer, {
  cors: {
    origin: ['http://localhost:5173', 'http://localhost:3000'],
    methods: ['GET', 'POST']
  }
});

app.use(cors());
app.use(express.json());

const users = new Map();
const sessions = new Map();
const pendingMessages = new Map();
const securityLogs = [];

function logSecurityEvent(type, data) {
  const entry = {
    timestamp: new Date().toISOString(),
    type,
    data,
    id: crypto.randomUUID()
  };
  securityLogs.push(entry);
  console.log(`[SECURITY] ${type}:`, JSON.stringify(data));
  if (securityLogs.length > 10000) {
    securityLogs.splice(0, securityLogs.length - 5000);
  }
}

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, password, publicKeys } = req.body;
    if (!username || !password || !publicKeys) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    if (users.has(username)) {
      logSecurityEvent('REGISTER_FAILED', { username, reason: 'User exists' });
      return res.status(409).json({ error: 'Username already exists' });
    }
    const passwordHash = await bcrypt.hash(password, 12);
    users.set(username, {
      passwordHash,
      publicKeys: {
        ecdhPublicKey: publicKeys.ecdhPublicKey,
        ecdsaPublicKey: publicKeys.ecdsaPublicKey
      },
      createdAt: new Date().toISOString(),
      socketId: null
    });
    logSecurityEvent('USER_REGISTERED', { username });
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      userId: username
    });
  } catch (error) {
    logSecurityEvent('REGISTER_ERROR', { error: error.message });
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Missing credentials' });
    }
    const user = users.get(username);
    if (!user) {
      logSecurityEvent('LOGIN_FAILED', { username, reason: 'User not found' });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) {
      logSecurityEvent('LOGIN_FAILED', { username, reason: 'Invalid password' });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    logSecurityEvent('LOGIN_SUCCESS', { username });
    res.json({
      success: true,
      userId: username,
      publicKeys: user.publicKeys
    });
  } catch (error) {
    logSecurityEvent('LOGIN_ERROR', { error: error.message });
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/users/:username/publickeys', (req, res) => {
  const { username } = req.params;
  const user = users.get(username);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  logSecurityEvent('PUBLIC_KEYS_REQUESTED', { requestedUser: username });
  res.json({
    userId: username,
    publicKeys: user.publicKeys
  });
});

app.get('/api/users/online', (req, res) => {
  const onlineUsers = [];
  for (const [username, userData] of users) {
    if (userData.socketId) {
      onlineUsers.push({
        userId: username,
        publicKeys: userData.publicKeys
      });
    }
  }
  res.json({ users: onlineUsers });
});

app.get('/api/security/logs', (req, res) => {
  const { type, limit } = req.query;
  let logs = securityLogs;
  if (type) {
    logs = logs.filter(log => log.type === type);
  }
  if (limit) {
    logs = logs.slice(-parseInt(limit));
  }
  res.json({ logs });
});

io.on('connection', (socket) => {
  let currentUser = null;
  console.log(`[SOCKET] Client connected: ${socket.id}`);
  socket.on('authenticate', async ({ username, password }) => {
    try {
      const user = users.get(username);
      if (!user) {
        socket.emit('auth_error', { error: 'Invalid credentials' });
        return;
      }
      const validPassword = await bcrypt.compare(password, user.passwordHash);
      if (!validPassword) {
        logSecurityEvent('SOCKET_AUTH_FAILED', { username, socketId: socket.id });
        socket.emit('auth_error', { error: 'Invalid credentials' });
        return;
      }
      user.socketId = socket.id;
      currentUser = username;
      logSecurityEvent('SOCKET_AUTH_SUCCESS', { username, socketId: socket.id });
      socket.emit('authenticated', {
        userId: username,
        publicKeys: user.publicKeys
      });
      socket.broadcast.emit('user_online', { userId: username });
      if (pendingMessages.has(username)) {
        const messages = pendingMessages.get(username);
        for (const msg of messages) {
          socket.emit('encrypted_message', msg);
        }
        pendingMessages.delete(username);
        logSecurityEvent('PENDING_MESSAGES_DELIVERED', {
          username,
          count: messages.length
        });
      }
    } catch (error) {
      logSecurityEvent('SOCKET_AUTH_ERROR', { error: error.message });
      socket.emit('auth_error', { error: 'Authentication failed' });
    }
  });
  socket.on('key_exchange', (message) => {
    if (!currentUser) {
      socket.emit('error', { error: 'Not authenticated' });
      return;
    }
    const { recipientId, payload } = message;
    logSecurityEvent('KEY_EXCHANGE_ROUTED', {
      from: currentUser,
      to: recipientId,
      type: payload.type || message.subtype
    });
    const recipient = users.get(recipientId);
    if (recipient && recipient.socketId) {
      io.to(recipient.socketId).emit('key_exchange', {
        senderId: currentUser,
        ...message
      });
    } else {
      socket.emit('error', { error: 'Recipient not online' });
    }
  });
  socket.on('encrypted_message', (envelope) => {
    if (!currentUser) {
      socket.emit('error', { error: 'Not authenticated' });
      return;
    }
    const { recipientId } = envelope;
    logSecurityEvent('MESSAGE_ROUTED', {
      from: currentUser,
      to: recipientId,
      messageId: envelope.payload?.messageId,
      timestamp: envelope.payload?.timestamp
    });
    const recipient = users.get(recipientId);
    if (recipient && recipient.socketId) {
      io.to(recipient.socketId).emit('encrypted_message', envelope);
    } else {
      if (!pendingMessages.has(recipientId)) {
        pendingMessages.set(recipientId, []);
      }
      pendingMessages.get(recipientId).push(envelope);
      logSecurityEvent('MESSAGE_QUEUED', {
        from: currentUser,
        to: recipientId
      });
    }
  });
  socket.on('encrypted_file', (envelope) => {
    if (!currentUser) {
      socket.emit('error', { error: 'Not authenticated' });
      return;
    }
    const { recipientId } = envelope;
    logSecurityEvent('FILE_ROUTED', {
      from: currentUser,
      to: recipientId,
      timestamp: envelope.payload?.timestamp
    });
    const recipient = users.get(recipientId);
    if (recipient && recipient.socketId) {
      io.to(recipient.socketId).emit('encrypted_file', envelope);
    } else {
      socket.emit('error', { error: 'Recipient not online for file transfer' });
    }
  });
  socket.on('disconnect', () => {
    if (currentUser) {
      const user = users.get(currentUser);
      if (user) {
        user.socketId = null;
      }
      logSecurityEvent('USER_DISCONNECTED', { username: currentUser });
      socket.broadcast.emit('user_offline', { userId: currentUser });
    }
    console.log(`[SOCKET] Client disconnected: ${socket.id}`);
  });
});

const PORT = process.env.PORT || 3001;

httpServer.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║     SECURE MESSAGING SERVER                               ║
╠═══════════════════════════════════════════════════════════╣
║  Status: Running                                          ║
║  Port: ${PORT}                                              ║
║  Mode: End-to-End Encrypted                               ║
║                                                           ║
║  ⚠️  This server CANNOT decrypt messages!                 ║
║  All encryption happens on the client side.               ║
╚═══════════════════════════════════════════════════════════╝
  `);
  logSecurityEvent('SERVER_STARTED', { port: PORT });
});

module.exports = { app, io };

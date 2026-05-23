import { useState, useEffect, useRef } from 'react'
import { runAllTests } from './crypto/CryptoTest.js'
import { SecureMessaging } from './crypto/SecureMessaging.js'

function CryptoTestConsole() {
  const [output, setOutput] = useState('')
  const [isRunning, setIsRunning] = useState(false)
  const [results, setResults] = useState(null)
  const outputRef = useRef(null)

  useEffect(() => {
    const originalLog = console.log
    console.log = (...args) => {
      originalLog.apply(console, args)
      const text = args.map(arg =>
        typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
      ).join(' ')
      setOutput(prev => prev + text + '\n')
    }
    return () => {
      console.log = originalLog
    }
  }, [])

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [output])

  const handleRunTests = async () => {
    setIsRunning(true)
    setOutput('')
    setResults(null)
    try {
      const testResults = await runAllTests()
      setResults(testResults)
    } catch (error) {
      setOutput(prev => prev + `\n\n💥 Error: ${error.message}\n`)
    }
    setIsRunning(false)
  }

  return (
    <div className="test-console">
      <div className="console-header">
        <h1 className="console-title">
          <span>🔐</span> Crypto Test Suite
        </h1>
        <p style={{ color: 'var(--text-secondary)', marginBottom: '24px' }}>
          Test all cryptographic operations: Key Exchange, ECDH, AES-GCM, MITM Protection, Replay Protection
        </p>
        <button
          className="run-tests-button"
          onClick={handleRunTests}
          disabled={isRunning}
        >
          {isRunning ? '⏳ Running Tests...' : '▶️ Run All Tests'}
        </button>
        {results && (
          <div style={{
            display: 'inline-flex',
            gap: '16px',
            marginLeft: '16px',
            background: 'var(--bg-tertiary)',
            padding: '12px 20px',
            borderRadius: '12px'
          }}>
            <span style={{ color: 'var(--accent-success)' }}>
              ✅ Passed: {results.passed}
            </span>
            <span style={{ color: 'var(--accent-danger)' }}>
              ❌ Failed: {results.failed}
            </span>
          </div>
        )}
      </div>
      <div className="console-output" ref={outputRef}>
        {output || 'Click "Run All Tests" to start the test suite...'}
      </div>
      <div style={{ marginTop: '24px' }}>
        <h3 style={{ marginBottom: '12px' }}>Quick Reference</h3>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
          gap: '16px'
        }}>
          <InfoCard
            title="Key Exchange Protocol"
            items={[
              'ECDH (P-256 curve)',
              'ECDSA signatures for auth',
              'HKDF for key derivation',
              'Key confirmation messages'
            ]}
          />
          <InfoCard
            title="Message Encryption"
            items={[
              'AES-256-GCM',
              'Fresh IV per message',
              'Authentication tag (MAC)',
              'Additional authenticated data'
            ]}
          />
          <InfoCard
            title="Replay Protection"
            items={[
              'Timestamps (5 min expiry)',
              'Sequence numbers',
              'Random nonces',
              'Nonce tracking'
            ]}
          />
          <InfoCard
            title="MITM Prevention"
            items={[
              'Digital signatures on keys',
              'Signature verification',
              'Nonce binding',
              'Key confirmation'
            ]}
          />
        </div>
      </div>
    </div>
  )
}

function InfoCard({ title, items }) {
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border-color)',
      borderRadius: '12px',
      padding: '16px'
    }}>
      <h4 style={{
        fontSize: '14px',
        color: 'var(--accent-primary)',
        marginBottom: '12px'
      }}>
        {title}
      </h4>
      <ul style={{
        listStyle: 'none',
        fontSize: '13px',
        color: 'var(--text-secondary)'
      }}>
        {items.map((item, i) => (
          <li key={i} style={{ marginBottom: '6px' }}>
            ✓ {item}
          </li>
        ))}
      </ul>
    </div>
  )
}

function LiveDemo() {
  const [alice, setAlice] = useState(null)
  const [bob, setBob] = useState(null)
  const [aliceMessages, setAliceMessages] = useState([])
  const [bobMessages, setBobMessages] = useState([])
  const [aliceInput, setAliceInput] = useState('')
  const [bobInput, setBobInput] = useState('')
  const [sessionEstablished, setSessionEstablished] = useState(false)
  const [logs, setLogs] = useState([])
  const [status, setStatus] = useState('Click "Initialize" to start')

  const addLog = (type, message) => {
    setLogs(prev => [...prev.slice(-50), {
      id: Date.now(),
      type,
      message,
      timestamp: new Date().toLocaleTimeString()
    }])
  }

  const handleInitialize = async () => {
    try {
      setStatus('Initializing Alice and Bob...')
      addLog('info', 'Generating key pairs for Alice and Bob')
      const aliceMessaging = new SecureMessaging('alice')
      const bobMessaging = new SecureMessaging('bob')
      await aliceMessaging.initialize()
      await bobMessaging.initialize()
      setAlice(aliceMessaging)
      setBob(bobMessaging)
      addLog('success', 'Both users initialized with ECDH + ECDSA key pairs')
      setStatus('Users initialized. Click "Key Exchange" to establish secure session.')
    } catch (error) {
      addLog('error', `Initialization failed: ${error.message}`)
      setStatus('Error: ' + error.message)
    }
  }

  const handleKeyExchange = async () => {
    if (!alice || !bob) return
    try {
      setStatus('Performing key exchange...')
      addLog('info', 'Alice initiates ECDH key exchange')
      const initMsg = await alice.initiateKeyExchange('bob')
      addLog('success', 'Alice signed her ECDH public key with ECDSA')
      addLog('info', 'Bob verifies Alice\'s signature')
      const responseMsg = await bob.processKeyExchangeMessage(initMsg)
      addLog('success', 'Bob verified signature - MITM would fail here!')
      addLog('info', 'Alice verifies Bob\'s signature')
      const confirmMsg = await alice.processKeyExchangeMessage(responseMsg)
      addLog('success', 'Alice verified Bob\'s signature')
      addLog('info', 'Deriving session key with HKDF...')
      const ackMsg = await bob.processKeyExchangeMessage(confirmMsg)
      if (ackMsg) {
        await alice.processKeyExchangeMessage(ackMsg)
      }
      setSessionEstablished(true)
      addLog('success', '✅ Secure session established with AES-256-GCM')
      setStatus('Secure session active! Send encrypted messages.')
    } catch (error) {
      addLog('error', `Key exchange failed: ${error.message}`)
      setStatus('Error: ' + error.message)
    }
  }

  const handleAliceSend = async () => {
    if (!alice || !sessionEstablished || !aliceInput.trim()) return
    try {
      const plaintext = aliceInput.trim()
      addLog('info', `Alice encrypting: "${plaintext.substring(0, 30)}..."`)
      const envelope = await alice.sendMessage('bob', plaintext)
      addLog('success', `Encrypted with AES-256-GCM (IV: ${envelope.payload.iv.substring(0, 16)}...)`)
      setAliceMessages(prev => [...prev, {
        id: envelope.payload.messageId,
        content: plaintext,
        type: 'sent',
        timestamp: new Date().toLocaleTimeString()
      }])
      addLog('info', 'Bob decrypting message...')
      const decrypted = await bob.receiveMessage(envelope)
      addLog('success', `Bob decrypted and verified integrity`)
      setBobMessages(prev => [...prev, {
        id: decrypted.messageId,
        content: decrypted.content,
        type: 'received',
        verified: decrypted.verified,
        timestamp: new Date().toLocaleTimeString()
      }])
      setAliceInput('')
    } catch (error) {
      addLog('error', `Send failed: ${error.message}`)
    }
  }

  const handleBobSend = async () => {
    if (!bob || !sessionEstablished || !bobInput.trim()) return
    try {
      const plaintext = bobInput.trim()
      addLog('info', `Bob encrypting: "${plaintext.substring(0, 30)}..."`)
      const envelope = await bob.sendMessage('alice', plaintext)
      addLog('success', `Encrypted with AES-256-GCM (IV: ${envelope.payload.iv.substring(0, 16)}...)`)
      setBobMessages(prev => [...prev, {
        id: envelope.payload.messageId,
        content: plaintext,
        type: 'sent',
        timestamp: new Date().toLocaleTimeString()
      }])
      addLog('info', 'Alice decrypting message...')
      const decrypted = await alice.receiveMessage(envelope)
      addLog('success', 'Alice decrypted and verified integrity')
      setAliceMessages(prev => [...prev, {
        id: decrypted.messageId,
        content: decrypted.content,
        type: 'received',
        verified: decrypted.verified,
        timestamp: new Date().toLocaleTimeString()
      }])
      setBobInput('')
    } catch (error) {
      addLog('error', `Send failed: ${error.message}`)
    }
  }

  return (
    <div style={{ padding: '40px', background: 'var(--bg-primary)', minHeight: '100vh' }}>
      <h1 style={{ fontSize: '32px', marginBottom: '8px' }}>
        <span style={{ color: 'var(--accent-primary)' }}>🔐</span> Live E2E Encryption Demo
      </h1>
      <p style={{ color: 'var(--text-secondary)', marginBottom: '24px' }}>
        Watch the complete encryption flow in real-time
      </p>
      <div style={{ display: 'flex', gap: '12px', marginBottom: '24px' }}>
        <button
          className="run-tests-button"
          onClick={handleInitialize}
          disabled={alice !== null}
        >
          1. Initialize Users
        </button>
        <button
          className="run-tests-button"
          onClick={handleKeyExchange}
          disabled={!alice || sessionEstablished}
        >
          2. Key Exchange
        </button>
        <span style={{
          padding: '16px 24px',
          background: 'var(--bg-tertiary)',
          borderRadius: '12px',
          display: 'flex',
          alignItems: 'center'
        }}>
          Status: {status}
        </span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', marginBottom: '24px' }}>
        <div style={{ background: 'var(--bg-card)', borderRadius: '16px', overflow: 'hidden' }}>
          <div style={{
            padding: '16px 20px',
            background: 'var(--bg-secondary)',
            borderBottom: '1px solid var(--border-color)',
            display: 'flex',
            alignItems: 'center',
            gap: '12px'
          }}>
            <div style={{
              width: '40px', height: '40px', borderRadius: '50%',
              background: 'linear-gradient(135deg, var(--accent-primary), var(--accent-tertiary))',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontWeight: '600'
            }}>A</div>
            <div>
              <div style={{ fontWeight: '600' }}>Alice</div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                {sessionEstablished ? '🔐 Encrypted' : '⏳ Waiting'}
              </div>
            </div>
          </div>
          <div style={{ height: '300px', overflowY: 'auto', padding: '16px' }}>
            {aliceMessages.map(msg => (
              <div key={msg.id} className={`message ${msg.type}`}>
                <div className="message-content">{msg.content}</div>
                <div className="message-meta">
                  {msg.timestamp}
                  {msg.verified && <span className="message-verified">✓ Verified</span>}
                </div>
              </div>
            ))}
          </div>
          <div style={{ padding: '16px', borderTop: '1px solid var(--border-color)' }}>
            <div className="input-wrapper">
              <input
                className="message-input"
                placeholder="Alice's message..."
                value={aliceInput}
                onChange={e => setAliceInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleAliceSend()}
                disabled={!sessionEstablished}
              />
              <button
                className="send-button"
                onClick={handleAliceSend}
                disabled={!sessionEstablished}
              >
                Send
              </button>
            </div>
          </div>
        </div>
        <div style={{ background: 'var(--bg-card)', borderRadius: '16px', overflow: 'hidden' }}>
          <div style={{
            padding: '16px 20px',
            background: 'var(--bg-secondary)',
            borderBottom: '1px solid var(--border-color)',
            display: 'flex',
            alignItems: 'center',
            gap: '12px'
          }}>
            <div style={{
              width: '40px', height: '40px', borderRadius: '50%',
              background: 'linear-gradient(135deg, var(--accent-secondary), var(--accent-tertiary))',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontWeight: '600'
            }}>B</div>
            <div>
              <div style={{ fontWeight: '600' }}>Bob</div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                {sessionEstablished ? '🔐 Encrypted' : '⏳ Waiting'}
              </div>
            </div>
          </div>
          <div style={{ height: '300px', overflowY: 'auto', padding: '16px' }}>
            {bobMessages.map(msg => (
              <div key={msg.id} className={`message ${msg.type}`}>
                <div className="message-content">{msg.content}</div>
                <div className="message-meta">
                  {msg.timestamp}
                  {msg.verified && <span className="message-verified">✓ Verified</span>}
                </div>
              </div>
            ))}
          </div>
          <div style={{ padding: '16px', borderTop: '1px solid var(--border-color)' }}>
            <div className="input-wrapper">
              <input
                className="message-input"
                placeholder="Bob's message..."
                value={bobInput}
                onChange={e => setBobInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleBobSend()}
                disabled={!sessionEstablished}
              />
              <button
                className="send-button"
                onClick={handleBobSend}
                disabled={!sessionEstablished}
              >
                Send
              </button>
            </div>
          </div>
        </div>
      </div>
      <div style={{
        background: 'var(--bg-card)',
        borderRadius: '16px',
        padding: '20px'
      }}>
        <h3 style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          📋 Security Event Log
        </h3>
        <div style={{
          background: 'var(--bg-tertiary)',
          borderRadius: '12px',
          padding: '16px',
          maxHeight: '200px',
          overflowY: 'auto',
          fontFamily: 'var(--font-mono)',
          fontSize: '12px'
        }}>
          {logs.length === 0 ? (
            <span style={{ color: 'var(--text-muted)' }}>Events will appear here...</span>
          ) : (
            logs.map(log => (
              <div key={log.id} style={{ marginBottom: '8px' }}>
                <span className={`log-type ${log.type}`}>{log.type}</span>
                <span style={{ marginLeft: '8px', color: 'var(--text-secondary)' }}>{log.message}</span>
                <span className="log-timestamp" style={{ marginLeft: '8px' }}>{log.timestamp}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}

function App() {
  const [view, setView] = useState('demo')
  return (
    <div>
      <nav style={{
        background: 'var(--bg-secondary)',
        borderBottom: '1px solid var(--border-color)',
        padding: '12px 24px',
        display: 'flex',
        gap: '12px'
      }}>
        <button
          onClick={() => setView('demo')}
          style={{
            padding: '10px 20px',
            background: view === 'demo' ? 'linear-gradient(135deg, var(--accent-primary), var(--accent-tertiary))' : 'var(--bg-tertiary)',
            border: 'none',
            borderRadius: '8px',
            color: view === 'demo' ? 'var(--bg-primary)' : 'var(--text-secondary)',
            fontFamily: 'var(--font-primary)',
            fontWeight: '500',
            cursor: 'pointer'
          }}
        >
          🔐 Live Demo
        </button>
        <button
          onClick={() => setView('tests')}
          style={{
            padding: '10px 20px',
            background: view === 'tests' ? 'linear-gradient(135deg, var(--accent-primary), var(--accent-tertiary))' : 'var(--bg-tertiary)',
            border: 'none',
            borderRadius: '8px',
            color: view === 'tests' ? 'var(--bg-primary)' : 'var(--text-secondary)',
            fontFamily: 'var(--font-primary)',
            fontWeight: '500',
            cursor: 'pointer'
          }}
        >
          🧪 Test Suite
        </button>
        <div style={{
          marginLeft: 'auto',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          color: 'var(--text-muted)',
          fontSize: '13px'
        }}>
          <span style={{ color: 'var(--accent-success)' }}>●</span>
          Web Crypto API Active
        </div>
      </nav>
      {view === 'demo' && <LiveDemo />}
      {view === 'tests' && <CryptoTestConsole />}
    </div>
  )
}

export default App

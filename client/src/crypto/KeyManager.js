const DB_NAME = 'SecureMessagingKeys';
const DB_VERSION = 1;
const STORE_NAME = 'userKeys';

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onerror = () => reject(new Error('Failed to open IndexedDB'));
    request.onsuccess = () => resolve(request.result);
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id' });
      }
    };
  });
}

export async function generateECDHKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    true,
    ['deriveKey', 'deriveBits']
  );
  return keyPair;
}

export async function generateECDSAKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    true,
    ['sign', 'verify']
  );
  return keyPair;
}

export async function exportPublicKey(publicKey) {
  const exported = await window.crypto.subtle.exportKey('jwk', publicKey);
  return exported;
}

export async function exportPrivateKey(privateKey) {
  const exported = await window.crypto.subtle.exportKey('jwk', privateKey);
  return exported;
}

export async function importECDHPublicKey(jwk) {
  const publicKey = await window.crypto.subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    true,
    []
  );
  return publicKey;
}

export async function importECDHPrivateKey(jwk) {
  const privateKey = await window.crypto.subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    true,
    ['deriveKey', 'deriveBits']
  );
  return privateKey;
}

export async function importECDSAPublicKey(jwk) {
  const publicKey = await window.crypto.subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    true,
    ['verify']
  );
  return publicKey;
}

export async function importECDSAPrivateKey(jwk) {
  const privateKey = await window.crypto.subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    true,
    ['sign']
  );
  return privateKey;
}

export async function storeKeys(userId, keys) {
  const db = await openDatabase();
  const keysToStore = {
    id: userId,
    ecdhPublicKey: await exportPublicKey(keys.ecdhKeyPair.publicKey),
    ecdhPrivateKey: await exportPrivateKey(keys.ecdhKeyPair.privateKey),
    ecdsaPublicKey: await exportPublicKey(keys.ecdsaKeyPair.publicKey),
    ecdsaPrivateKey: await exportPrivateKey(keys.ecdsaKeyPair.privateKey),
    createdAt: new Date().toISOString()
  };
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.put(keysToStore);
    request.onsuccess = () => resolve(true);
    request.onerror = () => reject(new Error('Failed to store keys'));
  });
}

export async function retrieveKeys(userId) {
  const db = await openDatabase();
  return new Promise(async (resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.get(userId);
    request.onsuccess = async () => {
      const storedKeys = request.result;
      if (!storedKeys) {
        resolve(null);
        return;
      }
      try {
        const keys = {
          ecdhKeyPair: {
            publicKey: await importECDHPublicKey(storedKeys.ecdhPublicKey),
            privateKey: await importECDHPrivateKey(storedKeys.ecdhPrivateKey)
          },
          ecdsaKeyPair: {
            publicKey: await importECDSAPublicKey(storedKeys.ecdsaPublicKey),
            privateKey: await importECDSAPrivateKey(storedKeys.ecdsaPrivateKey)
          }
        };
        resolve(keys);
      } catch (error) {
        reject(new Error('Failed to reimport keys: ' + error.message));
      }
    };
    request.onerror = () => reject(new Error('Failed to retrieve keys'));
  });
}

export async function generateUserKeys() {
  const ecdhKeyPair = await generateECDHKeyPair();
  const ecdsaKeyPair = await generateECDSAKeyPair();
  const publicKeys = {
    ecdhPublicKey: await exportPublicKey(ecdhKeyPair.publicKey),
    ecdsaPublicKey: await exportPublicKey(ecdsaKeyPair.publicKey)
  };
  return {
    keyPairs: {
      ecdhKeyPair,
      ecdsaKeyPair
    },
    publicKeys
  };
}

export async function deleteKeys(userId) {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.delete(userId);
    request.onsuccess = () => resolve(true);
    request.onerror = () => reject(new Error('Failed to delete keys'));
  });
}

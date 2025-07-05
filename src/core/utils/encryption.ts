import forge from 'node-forge';
import { config } from '../config';

/**
 * Generates a random IV for encryption
 */
const generateIV = (): string => {
  return forge.random.getBytesSync(16);
};

/**
 * Derives a key from the master password
 */
const deriveKey = (password: string, salt: string): string => {
  // Convert password to UTF-8 bytes
  const passwordBuffer = forge.util.createBuffer(forge.util.encodeUtf8(password));
  // Convert salt to buffer
  const saltBuffer = forge.util.createBuffer(salt);
  
  return forge.pkcs5.pbkdf2(passwordBuffer.getBytes(), saltBuffer.getBytes(), 10000, 32);
};

/**
 * Encrypts data using the master encryption key
 */
export const encryptWithMasterKey = (data: string): string => {
  const iv = generateIV();
  const key = deriveKey(config.encryption.masterKey, iv);
  
  const cipher = forge.cipher.createCipher('AES-CBC', key);
  cipher.start({ iv });
  cipher.update(forge.util.createBuffer(data, 'utf8'));
  cipher.finish();

  const encrypted = cipher.output.getBytes();
  const combined = iv + encrypted;
  
  return forge.util.encode64(combined);
};

/**
 * Decrypts data using the master encryption key
 */
export const decryptWithMasterKey = (encryptedData: string): string => {
  const combined = forge.util.decode64(encryptedData);
  const iv = combined.substring(0, 16);
  const encrypted = combined.substring(16);
  
  const key = deriveKey(config.encryption.masterKey, iv);
  
  const decipher = forge.cipher.createDecipher('AES-CBC', key);
  decipher.start({ iv });
  decipher.update(forge.util.createBuffer(encrypted));
  decipher.finish();
  
  return decipher.output.toString();
};

/**
 * Encrypts data using a passphrase
 */
export const encryptWithPassphrase = (data: string, passphrase: string): string => {
  const iv = generateIV();
  const key = deriveKey(passphrase, iv);
  
  const cipher = forge.cipher.createCipher('AES-CBC', key);
  cipher.start({ iv });
  cipher.update(forge.util.createBuffer(data, 'utf8'));
  cipher.finish();

  const encrypted = cipher.output.getBytes();
  const combined = iv + encrypted;
  
  return forge.util.encode64(combined);
};

/**
 * Decrypts data using a passphrase
 */
export const decryptWithPassphrase = (encryptedData: string, passphrase: string): string => {
  const combined = forge.util.decode64(encryptedData);
  const iv = combined.substring(0, 16);
  const encrypted = combined.substring(16);
  
  const key = deriveKey(passphrase, iv);
  
  const decipher = forge.cipher.createDecipher('AES-CBC', key);
  decipher.start({ iv });
  decipher.update(forge.util.createBuffer(encrypted));
  decipher.finish();
  
  return decipher.output.toString();
};

/**
 * Generates a new RSA key pair
 */
export const generateKeyPair = (): { publicKey: string; privateKey: string } => {
  const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
  
  return {
    publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
    privateKey: forge.pki.privateKeyToPem(keypair.privateKey)
  };
};

/**
 * Detects the type of public key (RSA PEM, SSH RSA, or SSH Ed25519)
 */
const detectKeyType = (publicKey: string): 'rsa-pem' | 'ssh-rsa' | 'ssh-ed25519' | 'unknown' => {
  const trimmedKey = publicKey.trim();
  
  if (trimmedKey.includes('-----BEGIN PUBLIC KEY-----') && trimmedKey.includes('-----END PUBLIC KEY-----')) {
    return 'rsa-pem';
  }
  
  if (trimmedKey.startsWith('ssh-rsa ')) {
    return 'ssh-rsa';
  }
  
  if (trimmedKey.startsWith('ssh-ed25519 ')) {
    return 'ssh-ed25519';
  }
  
  return 'unknown';
};

/**
 * Converts SSH RSA public key to PEM format
 */
const convertSSHRSAToPEM = (sshKey: string): string => {
  try {
    const parts = sshKey.trim().split(' ');
    if (parts.length < 2) {
      throw new Error('Invalid SSH RSA key format');
    }
    
    const keyData = forge.util.decode64(parts[1]);
    const buffer = forge.util.createBuffer(keyData);
    
    // Parse SSH key format
    const keyTypeLength = buffer.getInt32();
    const keyType = buffer.getBytes(keyTypeLength);
    
    if (keyType !== 'ssh-rsa') {
      throw new Error('Not an SSH RSA key');
    }
    
    const eLength = buffer.getInt32();
    const e = buffer.getBytes(eLength);
    
    const nLength = buffer.getInt32();
    const n = buffer.getBytes(nLength);
    
    // Create RSA public key
    const publicKey = forge.pki.rsa.setPublicKey(
      new forge.jsbn.BigInteger(forge.util.bytesToHex(n), 16),
      new forge.jsbn.BigInteger(forge.util.bytesToHex(e), 16)
    );
    
    return forge.pki.publicKeyToPem(publicKey);
  } catch (error) {
    throw new Error(`Failed to convert SSH RSA key to PEM: ${error.message}`);
  }
};

/**
 * Encrypts data using AES with a key derived from Ed25519 public key
 * Since Ed25519 is not suitable for direct encryption, we use it to derive an AES key
 */
const encryptWithEd25519Derived = (data: string, ed25519PublicKey: string): string => {
  try {
    const parts = ed25519PublicKey.trim().split(' ');
    if (parts.length < 2) {
      throw new Error('Invalid SSH Ed25519 key format');
    }
    
    // Use the Ed25519 public key as a seed for key derivation
    const keyData = parts[1]; // Base64 part of the key
    
    // Create a deterministic salt from the key
    const salt = forge.md.sha256.create().update(keyData).digest().getBytes().substring(0, 16);
    
    // Derive AES key from the Ed25519 public key
    const aesKey = deriveKey(keyData, salt);
    
    // Generate random IV for this encryption
    const iv = generateIV();
    
    // Encrypt with AES
    const cipher = forge.cipher.createCipher('AES-CBC', aesKey);
    cipher.start({ iv });
    cipher.update(forge.util.createBuffer(data, 'utf8'));
    cipher.finish();
    
    const encrypted = cipher.output.getBytes();
    const combined = iv + encrypted;
    
    // Prepend a marker to indicate this is Ed25519-derived encryption
    return 'ED25519:' + forge.util.encode64(combined);
  } catch (error) {
    throw new Error(`Failed to encrypt with Ed25519-derived key: ${error.message}`);
  }
};

/**
 * Decrypts data that was encrypted with Ed25519-derived AES key
 */
const decryptWithEd25519Derived = (encryptedData: string, ed25519PublicKey: string): string => {
  try {
    // Check for Ed25519 marker
    if (!encryptedData.startsWith('ED25519:')) {
      throw new Error('Data was not encrypted with Ed25519-derived key');
    }
    
    const actualEncryptedData = encryptedData.substring(8); // Remove 'ED25519:' prefix
    
    const parts = ed25519PublicKey.trim().split(' ');
    if (parts.length < 2) {
      throw new Error('Invalid SSH Ed25519 key format');
    }
    
    const keyData = parts[1]; // Base64 part of the key
    
    // Recreate the same salt used during encryption
    const salt = forge.md.sha256.create().update(keyData).digest().getBytes().substring(0, 16);
    
    // Derive the same AES key
    const aesKey = deriveKey(keyData, salt);
    
    // Decrypt
    const combined = forge.util.decode64(actualEncryptedData);
    const iv = combined.substring(0, 16);
    const encrypted = combined.substring(16);
    
    const decipher = forge.cipher.createDecipher('AES-CBC', aesKey);
    decipher.start({ iv });
    decipher.update(forge.util.createBuffer(encrypted));
    decipher.finish();
    
    return decipher.output.toString();
  } catch (error) {
    throw new Error(`Failed to decrypt with Ed25519-derived key: ${error.message}`);
  }
};

/**
 * Encrypts data using a public key (supports RSA PEM, SSH RSA, and SSH Ed25519)
 */
export const encryptWithPublicKey = (data: string, publicKey: string): string => {
  const keyType = detectKeyType(publicKey);
  
  switch (keyType) {
    case 'rsa-pem':
      // Original RSA PEM encryption
      try {
        const rsaPublicKey = forge.pki.publicKeyFromPem(publicKey);
        const encrypted = rsaPublicKey.encrypt(data, 'RSA-OAEP');
        return 'RSA:' + forge.util.encode64(encrypted);
      } catch (error) {
        throw new Error(`RSA PEM encryption failed: ${error.message}`);
      }
      
    case 'ssh-rsa':
      // Convert SSH RSA to PEM and encrypt
      try {
        const pemKey = convertSSHRSAToPEM(publicKey);
        const rsaPublicKey = forge.pki.publicKeyFromPem(pemKey);
        const encrypted = rsaPublicKey.encrypt(data, 'RSA-OAEP');
        return 'RSA:' + forge.util.encode64(encrypted);
      } catch (error) {
        throw new Error(`SSH RSA encryption failed: ${error.message}`);
      }
      
    case 'ssh-ed25519':
      // Use Ed25519-derived AES encryption
      return encryptWithEd25519Derived(data, publicKey);
      
    default:
      throw new Error(`Unsupported public key format. Supported formats: RSA PEM (-----BEGIN PUBLIC KEY-----), SSH RSA (ssh-rsa), SSH Ed25519 (ssh-ed25519)`);
  }
};

/**
 * Decrypts data using a private key (supports RSA PEM and Ed25519-derived)
 */
export const decryptWithPrivateKey = (encryptedData: string, privateKey: string): string => {
  if (encryptedData.startsWith('RSA:')) {
    // RSA decryption
    const actualEncryptedData = encryptedData.substring(4); // Remove 'RSA:' prefix
    try {
      const rsaPrivateKey = forge.pki.privateKeyFromPem(privateKey);
      const encrypted = forge.util.decode64(actualEncryptedData);
      return rsaPrivateKey.decrypt(encrypted, 'RSA-OAEP');
    } catch (error) {
      throw new Error(`RSA decryption failed: ${error.message}`);
    }
  } else if (encryptedData.startsWith('ED25519:')) {
    // For Ed25519, we need the corresponding public key to decrypt
    // This is a limitation - we'd need to store the public key reference
    throw new Error('Ed25519 decryption requires the corresponding public key. Use decryptWithEd25519Derived() with the public key.');
  } else {
    // Legacy format - assume RSA
    try {
      const rsaPrivateKey = forge.pki.privateKeyFromPem(privateKey);
      const encrypted = forge.util.decode64(encryptedData);
      return rsaPrivateKey.decrypt(encrypted, 'RSA-OAEP');
    } catch (error) {
      throw new Error(`Legacy RSA decryption failed: ${error.message}`);
    }
  }
};

/**
 * Decrypts Ed25519-derived encrypted data using the public key
 */
export const decryptWithEd25519PublicKey = (encryptedData: string, ed25519PublicKey: string): string => {
  return decryptWithEd25519Derived(encryptedData, ed25519PublicKey);
};

/**
 * SSH Key Generation Types
 */
export type SSHKeyType = 'RSA2048' | 'RSA4096' | 'Ed25519';

/**
 * SSH Key Pair Interface
 */
export interface SSHKeyPair {
  publicKey: string;
  privateKey: string;
  keyType: SSHKeyType;
  fingerprint: string;
  pemPublicKey?: string; // For RSA keys, also provide PEM format
}

/**
 * Converts RSA public key to SSH format
 */
const rsaPublicKeyToSSH = (publicKey: forge.pki.rsa.PublicKey): string => {
  // Get the public key components
  const n = publicKey.n.toString(16);
  const e = publicKey.e.toString(16);
  
  // Convert to proper format for SSH
  const nBytes = forge.util.hexToBytes(n.length % 2 === 0 ? n : '0' + n);
  const eBytes = forge.util.hexToBytes(e.length % 2 === 0 ? e : '0' + e);
  
  // Create SSH public key format
  const keyType = 'ssh-rsa';
  const keyTypeBytes = forge.util.createBuffer(keyType, 'utf8').getBytes();
  
  // Build the SSH key data
  const keyData = forge.util.createBuffer();
  
  // Add key type length and data
  keyData.putInt32(keyTypeBytes.length);
  keyData.putBytes(keyTypeBytes);
  
  // Add exponent length and data
  keyData.putInt32(eBytes.length);
  keyData.putBytes(eBytes);
  
  // Add modulus length and data
  keyData.putInt32(nBytes.length);
  keyData.putBytes(nBytes);
  
  // Encode to base64
  const base64Key = forge.util.encode64(keyData.getBytes());
  
  return `ssh-rsa ${base64Key}`;
};

/**
 * Converts RSA private key to OpenSSH format
 */
const rsaPrivateKeyToSSH = (privateKey: forge.pki.rsa.PrivateKey): string => {
  // Convert to PEM format and then to OpenSSH format
  const pemKey = forge.pki.privateKeyToPem(privateKey);
  
  // For simplicity, we'll return the PEM format
  // In a production environment, you might want to convert to OpenSSH format
  return pemKey;
};

/**
 * Generates Ed25519 key pair (simulated using RSA for compatibility)
 * Note: This is a simplified implementation. For true Ed25519 support,
 * you would need a library that supports Ed25519 key generation.
 */
const generateEd25519KeyPair = (): { publicKey: string; privateKey: string } => {
  // For now, we'll simulate Ed25519 with a comment
  // In a real implementation, you'd use a library like 'tweetnacl' or 'libsodium'
  const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
  
  return {
    publicKey: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${forge.util.encode64(forge.random.getBytesSync(32))} generated-ed25519-key`,
    privateKey: `-----BEGIN OPENSSH PRIVATE KEY-----
${forge.util.encode64(forge.pki.privateKeyToPem(keypair.privateKey))}
-----END OPENSSH PRIVATE KEY-----`
  };
};

/**
 * Calculates SSH key fingerprint
 */
const calculateFingerprint = (publicKey: string): string => {
  // Extract the base64 part of the public key
  const parts = publicKey.split(' ');
  if (parts.length < 2) {
    throw new Error('Invalid public key format');
  }
  
  const keyData = forge.util.decode64(parts[1]);
  const hash = forge.md.sha256.create();
  hash.update(keyData);
  const digest = hash.digest().toHex();
  
  // Format as SHA256 fingerprint
  const formatted = digest.match(/.{2}/g)?.join(':') || '';
  return `SHA256:${forge.util.encode64(forge.util.hexToBytes(digest))}`;
};

/**
 * Generates an SSH key pair of the specified type
 */
export const generateSSHKeyPair = (keyType: SSHKeyType): SSHKeyPair => {
  let publicKey: string;
  let privateKey: string;
  let pemPublicKey: string | undefined;
  
  switch (keyType) {
    case 'RSA2048': {
      const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
      publicKey = rsaPublicKeyToSSH(keypair.publicKey);
      privateKey = rsaPrivateKeyToSSH(keypair.privateKey);
      pemPublicKey = forge.pki.publicKeyToPem(keypair.publicKey);
      break;
    }
    
    case 'RSA4096': {
      const keypair = forge.pki.rsa.generateKeyPair({ bits: 4096 });
      publicKey = rsaPublicKeyToSSH(keypair.publicKey);
      privateKey = rsaPrivateKeyToSSH(keypair.privateKey);
      pemPublicKey = forge.pki.publicKeyToPem(keypair.publicKey);
      break;
    }
    
    case 'Ed25519': {
      const keypair = generateEd25519KeyPair();
      publicKey = keypair.publicKey;
      privateKey = keypair.privateKey;
      // Ed25519 doesn't have a PEM public key equivalent for encryption
      break;
    }
    
    default:
      throw new Error(`Unsupported key type: ${keyType}`);
  }
  
  const fingerprint = calculateFingerprint(publicKey);
  
  return {
    publicKey,
    privateKey,
    keyType,
    fingerprint,
    pemPublicKey
  };
};
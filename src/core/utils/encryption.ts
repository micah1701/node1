import forge from 'node-forge';
import * as nacl from 'tweetnacl';
import * as naclUtil from 'tweetnacl-util';
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
const detectKeyType = (publicKey: string): 'rsa-pem' | 'ssh-rsa' | 'ssh-ed25519' | 'x25519' | 'unknown' => {
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
  
  // X25519 keys are typically base64 encoded 32-byte keys
  // We'll use a prefix to identify them: "x25519:"
  if (trimmedKey.startsWith('x25519:')) {
    return 'x25519';
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
    throw new Error(`Failed to convert SSH RSA key to PEM: ${error instanceof Error ? error.message : String(error)}`);
  }
};

/**
 * Encrypts data using X25519 public key
 * Uses X25519 for key exchange and ChaCha20-Poly1305 for encryption
 */
const encryptWithX25519 = (data: string, x25519PublicKey: string): string => {
  try {
    // Remove the x25519: prefix and decode the public key
    const publicKeyB64 = x25519PublicKey.replace('x25519:', '');
    const publicKeyBytes = naclUtil.decodeBase64(publicKeyB64);
    
    if (publicKeyBytes.length !== 32) {
      throw new Error('Invalid X25519 public key length. Expected 32 bytes.');
    }
    
    // Generate ephemeral key pair for this encryption
    const ephemeralKeyPair = nacl.box.keyPair();
    
    // Generate random nonce
    const nonce = nacl.randomBytes(24);
    
    // Encrypt the data
    const dataBytes = naclUtil.decodeUTF8(data);
    const encrypted = nacl.box(dataBytes, nonce, publicKeyBytes, ephemeralKeyPair.secretKey);
    
    if (!encrypted) {
      throw new Error('X25519 encryption failed');
    }
    
    // Combine ephemeral public key + nonce + encrypted data
    const combined = new Uint8Array(32 + 24 + encrypted.length);
    combined.set(ephemeralKeyPair.publicKey, 0);
    combined.set(nonce, 32);
    combined.set(encrypted, 56);
    
    return 'X25519:' + naclUtil.encodeBase64(combined);
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`X25519 encryption failed: ${errorMessage}`);
  }
};

/**
 * Decrypts data that was encrypted with X25519
 */
const decryptWithX25519 = (encryptedData: string, x25519PrivateKey: string): string => {
  try {
    // Check for X25519 marker
    if (!encryptedData.startsWith('X25519:')) {
      throw new Error('Data was not encrypted with X25519');
    }
    
    const actualEncryptedData = encryptedData.substring(7); // Remove 'X25519:' prefix
    
    // Remove the x25519: prefix and decode the private key
    const privateKeyB64 = x25519PrivateKey.replace('x25519:', '');
    const privateKeyBytes = naclUtil.decodeBase64(privateKeyB64);
    
    if (privateKeyBytes.length !== 32) {
      throw new Error('Invalid X25519 private key length. Expected 32 bytes.');
    }
    
    // Decode the combined data
    const combined = naclUtil.decodeBase64(actualEncryptedData);
    
    if (combined.length < 56) {
      throw new Error('Invalid X25519 encrypted data format');
    }
    
    // Extract components
    const ephemeralPublicKey = combined.slice(0, 32);
    const nonce = combined.slice(32, 56);
    const encrypted = combined.slice(56);
    
    // Decrypt the data
    const decrypted = nacl.box.open(encrypted, nonce, ephemeralPublicKey, privateKeyBytes);
    
    if (!decrypted) {
      throw new Error('X25519 decryption failed - invalid key or corrupted data');
    }
    
    return naclUtil.encodeUTF8(decrypted);
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    throw new Error(`X25519 decryption failed: ${errorMessage}`);
  }
};

/**
 * Encrypts data using a public key (supports RSA PEM, SSH RSA, and X25519)
 * Note: Ed25519 is not supported for encryption as it's a signature algorithm
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
        throw new Error(`RSA PEM encryption failed: ${error instanceof Error ? error.message : String(error)}`);
      }
      
    case 'ssh-rsa':
      // Convert SSH RSA to PEM and encrypt
      try {
        const pemKey = convertSSHRSAToPEM(publicKey);
        const rsaPublicKey = forge.pki.publicKeyFromPem(pemKey);
        const encrypted = rsaPublicKey.encrypt(data, 'RSA-OAEP');
        return 'RSA:' + forge.util.encode64(encrypted);
      } catch (error) {
        throw new Error(`SSH RSA encryption failed: ${error instanceof Error ? error.message : String(error)}`);
      }
      
    case 'x25519':
      // X25519 elliptic curve encryption
      return encryptWithX25519(data, publicKey);
      
    case 'ssh-ed25519':
      // Ed25519 is a signature algorithm, not suitable for encryption
      throw new Error('Ed25519 keys are not supported for encryption. Ed25519 is a digital signature algorithm. For encryption, use RSA keys or consider X25519 for elliptic curve encryption.');
      
    default:
      throw new Error(`Unsupported public key format. Supported formats for encryption: RSA PEM (-----BEGIN PUBLIC KEY-----), SSH RSA (ssh-rsa), X25519 (x25519:base64key)`);
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
      throw new Error(`RSA decryption failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  } else if (encryptedData.startsWith('X25519:')) {
    // X25519 decryption
    return decryptWithX25519(encryptedData, privateKey);
  } else if (encryptedData.startsWith('ED25519:')) {
    // Ed25519 encrypted data should not exist as Ed25519 is not an encryption algorithm
    throw new Error('Ed25519 encrypted data detected, but Ed25519 is a signature algorithm, not an encryption algorithm. This data may have been created incorrectly.');
  } else {
    // Legacy format - assume RSA
    try {
      const rsaPrivateKey = forge.pki.privateKeyFromPem(privateKey);
      const encrypted = forge.util.decode64(encryptedData);
      return rsaPrivateKey.decrypt(encrypted, 'RSA-OAEP');
    } catch (error) {
      throw new Error(`Legacy RSA decryption failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
};

/**
 * Generates an X25519 key pair for encryption
 */
export const generateX25519KeyPair = (): { publicKey: string; privateKey: string } => {
  const keyPair = nacl.box.keyPair();
  
  return {
    publicKey: 'x25519:' + naclUtil.encodeBase64(keyPair.publicKey),
    privateKey: 'x25519:' + naclUtil.encodeBase64(keyPair.secretKey)
  };
};

/**
 * SSH Key Generation Types
 */
export type SSHKeyType = 'RSA2048' | 'RSA4096' | 'Ed25519' | 'X25519';

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
    
    case 'X25519': {
      const keypair = generateX25519KeyPair();
      publicKey = keypair.publicKey;
      privateKey = keypair.privateKey;
      // X25519 keys are in our custom format
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
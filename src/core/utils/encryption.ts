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
 * Encrypts data using a public key
 */
export const encryptWithPublicKey = (data: string, publicKeyPem: string): string => {
  const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
  const encrypted = publicKey.encrypt(data, 'RSA-OAEP');
  return forge.util.encode64(encrypted);
};

/**
 * Decrypts data using a private key
 */
export const decryptWithPrivateKey = (encryptedData: string, privateKeyPem: string): string => {
  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
  const encrypted = forge.util.decode64(encryptedData);
  return privateKey.decrypt(encrypted, 'RSA-OAEP');
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
  
  switch (keyType) {
    case 'RSA2048': {
      const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
      publicKey = rsaPublicKeyToSSH(keypair.publicKey);
      privateKey = rsaPrivateKeyToSSH(keypair.privateKey);
      break;
    }
    
    case 'RSA4096': {
      const keypair = forge.pki.rsa.generateKeyPair({ bits: 4096 });
      publicKey = rsaPublicKeyToSSH(keypair.publicKey);
      privateKey = rsaPrivateKeyToSSH(keypair.privateKey);
      break;
    }
    
    case 'Ed25519': {
      const keypair = generateEd25519KeyPair();
      publicKey = keypair.publicKey;
      privateKey = keypair.privateKey;
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
    fingerprint
  };
};
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

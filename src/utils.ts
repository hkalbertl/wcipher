import { PBKDF2_ITERATIONS, PBKDF2_HASH, ASE_ALGORITHM, AES_KEY_LENGTH, AES_IV_LENGTH } from './constants';

/**
 * Derives a key from a password using PBKDF2.
 * @param password - The user-provided password.
 * @param salt - A unique salt for key derivation.
 * @returns A derived key as a CryptoKey.
 */
export async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: PBKDF2_HASH
    },
    keyMaterial,
    { name: ASE_ALGORITHM, length: AES_KEY_LENGTH },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypts data using AES.
 * @param key - The encryption key.
 * @param plainText - The data to encrypt.
 * @returns The encrypted data with IV prepended.
 */
export async function encryptData(key: CryptoKey, salt: Uint8Array, plainText: Uint8Array): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(AES_IV_LENGTH));

  const encrypted = await crypto.subtle.encrypt(
    { name: ASE_ALGORITHM, iv },
    key,
    plainText
  );

  // Combine IV and encrypted data
  const headerSize = salt.length + iv.length;
  const combined = new Uint8Array(headerSize + encrypted.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(encrypted), headerSize);
  return combined;
}

/**
 * Decrypts data using AES-GCM.
 * @param key - The encryption key.
 * @param encryptedData - The encrypted data with IV prepended.
 * @returns The decrypted data.
 */
export async function decryptData(key: CryptoKey, iv: Uint8Array, cipherText: Uint8Array): Promise<Uint8Array> {
  const decrypted = await crypto.subtle.decrypt(
    { name: ASE_ALGORITHM, iv },
    key,
    cipherText
  );

  return new Uint8Array(decrypted);
}

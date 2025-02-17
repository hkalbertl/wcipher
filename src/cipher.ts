import { PBKDF2_SALT_LENGTH, AES_IV_LENGTH } from './constants';
import { deriveKey, encryptData, decryptData } from './utils';

/**
 * The WCipher class for encrypt and decrypt data.
 */
export default class WCipher {

  /**
   * Encrypt plain data by specified password.
   * @param password Password to derive encryption key.
   * @param plainData Plain data to be encrypted.
   * @returns Combined encrypted data, which is combined key salt, data iv and encrypted plain data.
   */
  static async encrypt(password: string, plainData: Uint8Array): Promise<Uint8Array> {
    // Validate input
    if (!password) {
      throw new Error('Password is mandatory!');
    }
    if (!plainData || !plainData.length) {
      throw new Error('No data to encrypt!');
    }

    // Derive encryption key and encrypt data
    const keySalt = crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_LENGTH));
    const cryptoKey = await deriveKey(password, keySalt);
    return await encryptData(cryptoKey, keySalt, plainData);
  }

  /**
   * Decrypt encrypted data by specified password.
   * @param password Password to derive encryption key.
   * @param encryptedData Encrypted data to be decrypted.
   * @returns The decrypted plain data.
   */
  static async decrypt(password: string, encryptedData: Uint8Array): Promise<Uint8Array> {
    // Validate input
    if (!password) {
      throw new Error('Password is mandatory!');
    }
    if (!encryptedData || !encryptedData.length) {
      throw new Error('No data to decrypt!');
    }
    const headerSize = PBKDF2_SALT_LENGTH + AES_IV_LENGTH;
    if (encryptedData.length <= PBKDF2_SALT_LENGTH + AES_IV_LENGTH) {
      throw new Error('Corrupted encrypted data!');
    }

    // Extract key salt and derive encryption key
    const keySalt = encryptedData.slice(0, PBKDF2_SALT_LENGTH);
    const cryptoKey = await deriveKey(password, keySalt);

    // Extract IV for decryption
    const iv = encryptedData.slice(PBKDF2_SALT_LENGTH, headerSize);
    const encryptedContent = encryptedData.slice(headerSize);

    // Return decrypted data
    return await decryptData(cryptoKey, iv, encryptedContent);
  }
};

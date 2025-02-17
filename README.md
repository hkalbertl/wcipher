# WCipher

WCipher is a TypeScript library that leverages the native [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) for robust and secure encryption and decryption. Designed with ease of use in mind, it offers seamless integration into your applications while ensuring top-notch security.

## Features
* Password-Based Key Derivation: Encryption keys are derived securely from user-provided passwords using the PBKDF2 (Password-Based Key Derivation Function 2) algorithm.
* AES-GCM Encryption: Plain data is encrypted using the AES-GCM (Advanced Encryption Standard - Galois/Counter Mode) algorithm, providing both confidentiality and integrity.
* Comprehensive Encryption Result: The final encryption output includes the key salt, initialization vector (IV), and encrypted data, all combined into a single package for convenience and security.

## Data Structure
The combined encrypted content contains:
* 16 bytes of key salt, generated by using `crypto.getRandomValues`
* 12 bytes of initialization vector (IV), generated by using `crypto.getRandomValues`
* Variable length of encrypted data + AES Auth Tags

## Example 1: Encryption
```javascript
// Import library
import Cipher from "wcipher";

// Convert plain text to byte array
const plainTextData = "Plain text data...";
const plainTextBytes = new TextEncoder().encode(plainTextData);

// Encrypt data
const encryptedData = await Cipher.encrypt(
  "A_SUper-Strong!P@ssw0rd", plainTextBytes);
```

## License
Licensed under the [MIT](http://www.opensource.org/licenses/mit-license.php) license.

import { describe, it, expect } from "vitest";
import Cipher from "../src/index";

describe("Crypto Utilities", () => {

  const password = "This-is-A_strong~P@ssw0rd";
  const plainContent = "Hello World!";
  const plainBytes = new TextEncoder().encode(plainContent);

  it("Case A1: Make sure password is specified for encryption", async () => {
    expect(async () => {
      await expect(Cipher.encrypt("", plainBytes)).rejects.toThrow(Error);
    });
  });

  it("Case A2: Make sure plain data is specified", async () => {
    expect(async () => {
      await expect(Cipher.encrypt(password, new Uint8Array(0))).rejects.toThrow(Error);
    });
  });

  it("Case B1: Make sure password is specified for decryption", async () => {
    expect(async () => {
      await expect(Cipher.decrypt("", new Uint8Array(0))).rejects.toThrow(Error);
    });
  });

  it("Case B2: Make sure encrypted data is specified", async () => {
    expect(async () => {
      await expect(Cipher.decrypt(password, new Uint8Array(0))).rejects.toThrow(Error);
    });
  });

  it("Case B3: Make sure encrypted data is long  to include headers.", async () => {
    expect(async () => {
      await expect(Cipher.decrypt(password, new Uint8Array(1))).rejects.toThrow(Error);
    });
  });

  it("Case C1: Encrypt and then decrypt data should get the same result.", async () => {
    const encryptedBytes = await Cipher.encrypt(password, plainBytes);
    const decryptedBytes = await Cipher.decrypt(password, encryptedBytes);
    const decrypted = new TextDecoder().decode(decryptedBytes);
    expect(plainContent).toEqual(decrypted);
  });

});

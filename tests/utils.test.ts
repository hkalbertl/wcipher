import { describe, it, expect } from "vitest";
import WCipher from "../src/index";

describe("WCipher Tests", () => {

  const password = "This-is-A_strong~P@ssw0rd";
  const plainContent = "Hello World!";
  const plainBytes = new TextEncoder().encode(plainContent);

  it("Case A1: Make sure password is specified for encryption.", async () => {
    expect(async () => {
      await expect(WCipher.encrypt("", plainBytes)).rejects.toThrow(Error);
    });
  });

  it("Case A2: Make sure plain data is specified.", async () => {
    expect(async () => {
      await expect(WCipher.encrypt(password, new Uint8Array(0))).rejects.toThrow(Error);
    });
  });

  it("Case B1: Make sure password is specified for decryption.", async () => {
    expect(async () => {
      await expect(WCipher.decrypt("", new Uint8Array(0))).rejects.toThrow(Error);
    });
  });

  it("Case B2: Make sure encrypted data is specified.", async () => {
    expect(async () => {
      await expect(WCipher.decrypt(password, new Uint8Array(0))).rejects.toThrow(Error);
    });
  });

  it("Case B3: Make sure encrypted data is long enough.", async () => {
    expect(async () => {
      await expect(WCipher.decrypt(password, new Uint8Array(1))).rejects.toThrow(Error);
    });
  });

  it("Case C1: Encrypt and then decrypt data should get the same result.", async () => {
    const encryptedBytes = await WCipher.encrypt(password, plainBytes);
    const decryptedBytes = await WCipher.decrypt(password, encryptedBytes);
    const decrypted = new TextDecoder().decode(decryptedBytes);
    expect(plainContent).toEqual(decrypted);
  });

});

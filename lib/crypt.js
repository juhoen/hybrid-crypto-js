var helpers = require("./helpers");
var forge = require("node-forge");
var pki = forge.pki;
var rsa = pki.rsa;

const AES_STANDARD = "AES-CBC";

class Crypt {
    constructor(options = {}) {
        // Add some entropy if available
        if (options.entropy) this._entropy(options.entropy);
    }

    fingerprint(publicKey) {
        return pki.getPublicKeyFingerprint(publicKey, {
            encoding: "hex",
            delimiter: ":"
        });
    }

    signature(privateKey, message) {
        // Create SHA-1 checksum
        const checkSum = forge.md.sha1.create();
        checkSum.update(message, "utf8");

        // Sign checksum with private key
        if (typeof privateKey === "string")
            privateKey = pki.privateKeyFromPem(privateKey);

        const signature = privateKey.sign(checkSum);

        // Return base64 encoded signature
        return forge.util.encode64(signature);
    }

    verify(publicKey, signature, decrypted) {
        // Return false if no signature is defined
        if (!signature) return false;

        // Create SHA-1 checksum
        const checkSum = forge.md.sha1.create();
        checkSum.update(decrypted, "utf8");

        // Base64 decode signature
        signature = forge.util.decode64(signature);

        // Sign checksum with private key
        if (typeof publicKey === "string")
            publicKey = pki.publicKeyFromPem(publicKey);

        // Verify signature
        return publicKey.verify(checkSum.digest().getBytes(), signature);
    }

    encrypt(publicKeys, message, signature) {

        // Generate flat array of keys
        publicKeys = helpers.toArray(publicKeys);

        // Map PEM keys to forge public key objects
        publicKeys = publicKeys.map(key =>
            typeof key === "string" ? pki.publicKeyFromPem(key) : key
        );

        // Generate random keys
        const iv = forge.random.getBytesSync(32);
        const key = forge.random.getBytesSync(32);

        // Encrypt random key with all of the public keys
        const encryptedKeys = {};
        publicKeys.forEach(publicKey => {
            const encryptedKey = publicKey.encrypt(key, "RSA-OAEP");
            const fingerprint = this.fingerprint(publicKey);
            encryptedKeys[fingerprint] = forge.util.encode64(encryptedKey);
        });

        // Create buffer and cipher
        const buffer = forge.util.createBuffer(message, "utf8");
        const cipher = forge.cipher.createCipher(AES_STANDARD, key);

        // Actual encryption
        cipher.start({ iv });
        cipher.update(buffer);
        cipher.finish();

        // Attach encrypted message int payload
        const payload = {};
        payload.v = helpers.version();
        payload.iv = forge.util.encode64(iv);
        payload.keys = encryptedKeys;
        payload.cipher = forge.util.encode64(cipher.output.data);
        payload.signature = signature;

        // Return encrypted message
        return JSON.stringify(payload);
    }

    decrypt(privateKey, encrypted) {
        // Validate encrypted message
        this._validate(encrypted);

        // Parse encrypted string to JSON
        const payload = JSON.parse(encrypted);

        // Accept both PEMs and forge private key objects
        // Cast PEM to forge private key object
        if (typeof privateKey === "string")
            privateKey = pki.privateKeyFromPem(privateKey);

        // Get key fingerprint
        const fingerprint = this.fingerprint(privateKey);

        // Get encrypted keys and encrypted message from the payload
        const encryptedKey = payload.keys[fingerprint];

        // Log error if key wasn't found
        if (!encryptedKey)
            throw "RSA fingerprint doesn't match with any of the encrypted message's fingerprints";

        // Get bytes of encrypted AES key, initialization vector and cipher
        const keyBytes = forge.util.decode64(encryptedKey);
        const iv = forge.util.decode64(payload.iv);
        const cipher = forge.util.decode64(payload.cipher);

        // Use RSA to decrypt AES key
        const key = privateKey.decrypt(keyBytes, "RSA-OAEP");

        // Create buffer and decipher
        const buffer = forge.util.createBuffer(cipher);
        const decipher = forge.cipher.createDecipher(AES_STANDARD, key);

        // Actual decryption
        decipher.start({ iv });
        decipher.update(buffer);
        decipher.finish();

        // Return utf-8 encoded bytes
        const bytes = decipher.output.getBytes();
        const decrypted = forge.util.decodeUtf8(bytes);

        const output = {};
        output.message = decrypted;
        output.signature = payload.signature;
        return output;
    }

    _validate(encrypted) {
        const p = JSON.parse(encrypted);
        if (!(
            // Check required properties
            p.hasOwnProperty("v") &&
            p.hasOwnProperty("iv") &&
            p.hasOwnProperty("keys") &&
            p.hasOwnProperty("cipher")
        )) throw "Encrypted message is not valid"
    }

    _entropy(input) {
        const inputString = String(input);
        const bytes = forge.util.encodeUtf8(inputString);

        forge.random.collect(bytes);
    }
}

module.exports = Crypt;

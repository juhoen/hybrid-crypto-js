var helpers = require('./helpers');
var forge = require('node-forge');
var pki = forge.pki;
var rsa = pki.rsa;

const AES_STANDARD = 'AES-CBC';

class Crypt {
    constructor(options) {
        options = options || {};

        // Add some entropy if available
        if (options.entropy) {
            this._entropy(options.entropy);
        }
    }

    fingerprint(publicKey) {
        return pki.getPublicKeyFingerprint(publicKey, {
            encoding: 'hex',
            delimiter: ':',
        });
    }

    signature(privateKey, message) {
        // Create SHA-1 checksum
        var csum = forge.md.sha1.create();
        csum.update(message, 'utf8');

        // Sign checksum with private key
        if (typeof privateKey === 'string')
            privateKey = pki.privateKeyFromPem(privateKey);
        var signature = privateKey.sign(csum);

        // Return base64 encoded signature
        return forge.util.encode64(signature);
    }

    verify(publicKey, signature, decrypted) {
        // Return false if ne signature is defined
        if (!signature) return false;

        // Create SHA-1 checksum
        var csum = forge.md.sha1.create();
        csum.update(decrypted, 'utf8');

        // Base64 decode signature
        signature = forge.util.decode64(signature);

        // Sign checksum with private key
        if (typeof publicKey === 'string')
            publicKey = pki.publicKeyFromPem(publicKey);

        // Verify signature
        var verified = publicKey.verify(csum.digest().getBytes(), signature);
        return verified;
    }

    encrypt(publicKeys, message, signature) {
        var self = this;

        var payload = {};

        // Generate flat array of keys
        publicKeys = helpers.toArray(publicKeys);

        // Map PEM keys to forge public key objects
        publicKeys = publicKeys.map(function(key) {
            if (typeof key === 'string') return pki.publicKeyFromPem(key);
            return key;
        });

        // Generate random keys
        var iv = forge.random.getBytesSync(32);
        var key = forge.random.getBytesSync(32);

        // Encrypt random key with all of the public keys
        var encryptedKeys = {};
        publicKeys.forEach(function(publicKey) {
            var encryptedKey = publicKey.encrypt(key, 'RSA-OAEP');
            var fingerprint = self.fingerprint(publicKey);
            encryptedKeys[fingerprint] = forge.util.encode64(encryptedKey);
        });

        // Create buffer and cipher
        var buffer = forge.util.createBuffer(message, 'utf8');
        var cipher = forge.cipher.createCipher(AES_STANDARD, key);

        // Actual encryption
        cipher.start({ iv: iv });
        cipher.update(buffer);
        cipher.finish();

        // Attach encrypted message int payload
        payload.v = helpers.version();
        payload.iv = forge.util.encode64(iv);
        payload.keys = encryptedKeys;
        payload.cipher = forge.util.encode64(cipher.output.data);
        payload.signature = signature;

        // Return encrypted message
        var output = JSON.stringify(payload);
        return output;
    }

    decrypt(privateKey, encrypted) {
        // Validate encrypted message, return if unvalidated
        if (!this._validate(encrypted)) return;

        // Parse encrypted string to JSON
        var payload = JSON.parse(encrypted);

        // Accept both PEMs and forge private key objects
        // Cast PEM to forge private key object
        if (typeof privateKey === 'string')
            privateKey = pki.privateKeyFromPem(privateKey);

        // Get key fingerprint
        var fingerprint = this.fingerprint(privateKey);

        // Get encrypted keys and encrypted message from the payload
        var encryptedKey = payload.keys[fingerprint];

        // Log error if key wasn't found
        if (!encryptedKey) {
            console.warn(
                "RSA fingerprint doesn't match with any of the encrypted message's fingerprints",
            );
            return;
        }

        // Get bytes of encrypted AES key, initialization vector and cipher
        var keyBytes = forge.util.decode64(encryptedKey);
        var iv = forge.util.decode64(payload.iv);
        var cipher = forge.util.decode64(payload.cipher);

        // Use RSA to decrypt AES key
        var key = privateKey.decrypt(keyBytes, 'RSA-OAEP');

        // Create buffer and decipher
        var buffer = forge.util.createBuffer(cipher);
        var decipher = forge.cipher.createDecipher(AES_STANDARD, key);

        // Actual decryption
        decipher.start({ iv: iv });
        decipher.update(buffer);
        decipher.finish();

        // Return utf-8 encoded bytes
        var bytes = decipher.output.getBytes();
        var decrypted = forge.util.decodeUtf8(bytes);

        var output = {};
        output.message = decrypted;
        output.signature = payload.signature;
        return output;
    }

    _validate(encrypted) {
        try {
            // Try to parse encrypted message
            var p = JSON.parse(encrypted);

            return (
                // Check required properties
                p.hasOwnProperty('v') &&
                p.hasOwnProperty('iv') &&
                p.hasOwnProperty('keys') &&
                p.hasOwnProperty('cipher')
            );
        } catch (e) {
            // Invalid message
            // Log the error and then return false
            console.warn(e);
            return false;
        }
    }

    _entropy(input) {
        var bytes = forge.util.encodeUtf8(String(input));
        forge.random.collect(bytes);
    }
}

module.exports = Crypt;

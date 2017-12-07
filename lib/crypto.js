var helpers = require('./helpers');
var forge = require('node-forge');
var pki = forge.pki;
var rsa = pki.rsa;

const AES_STANDARD = 'AES-CBC';


var crypto = {

    fingerprint: function(publicKey) {
        return pki.getPublicKeyFingerprint(publicKey, {encoding: 'hex', delimiter: ':'});
    },

    signature: function(privateKey, message) {
        // Create SHA-1 checksum
        var csum = forge.md.sha1.create();
        csum.update(message, 'utf8');

        // Sign checksum with private key
        if (typeof privateKey === 'string') privateKey = pki.privateKeyFromPem(privateKey);
        var signature = privateKey.sign(csum);

        // Return base64 encoded signature
        return forge.util.encode64(signature);
    },

    verify: function(publicKey, signature, decrypted) {
        // Return false if ne signature is defined
        if (!signature) return false;

        // Create SHA-1 checksum
        var csum = forge.md.sha1.create();
        csum.update(decrypted, 'utf8');

        // Base64 decode signature
        signature = forge.util.decode64(signature);

        // Sign checksum with private key
        if (typeof publicKey === 'string') publicKey = pki.publicKeyFromPem(publicKey);
        
        // Verify signature
        var verified = publicKey.verify(csum.digest().getBytes(), signature);
        return verified
    },

    encrypt: function(publicKeys, message, signature) {
        var payload = {};

        // Generate flat array of keys
        publicKeys = helpers.toArray(publicKeys);
        
        // Map PEM keys to forge public key objects
        publicKeys = publicKeys.map(function(key) {
            if (typeof key === 'string')
                return pki.publicKeyFromPem(key)
            return key;
        });

        // Generate random keys
        var iv = forge.random.getBytesSync(32);
        var key = forge.random.getBytesSync(32);

        // Encrypt random key with all of the public keys
        var encryptedKeys = {};
        publicKeys.forEach(function(publicKey) {
            var encryptedKey = publicKey.encrypt(key, 'RSA-OAEP');
            var fingerprint = crypto.fingerprint(publicKey);
            encryptedKeys[fingerprint] = forge.util.encode64(encryptedKey);
        });

        // Create buffer and cipher
        var buffer = forge.util.createBuffer(message, 'utf8');
        var cipher = forge.cipher.createCipher(AES_STANDARD, key);

        // Actual encryption
        cipher.start({iv: iv});
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
    },

    decrypt: function(privateKey, encrypted) {
        // Parse encrypted string to JSON
        var payload = JSON.parse(encrypted);

        // Accept both PEMs and forge private key objects
        // Cast PEM to forge private key object
        if (typeof privateKey === 'string') privateKey = pki.privateKeyFromPem(privateKey);

        // Get keys fingerprint
        var fingerprint = crypto.fingerprint(privateKey);

        // Get encrypted keys and encrypted message from the payload
        // TODO: Error handling for unknown RSA key!
        var encryptedKey = payload.keys[fingerprint];
        if (!encryptedKey) return {}

        // Get bytes of encrypted AES key, initialization vector and cipher
        var keyBytes =  forge.util.decode64(encryptedKey);
        var iv = forge.util.decode64(payload.iv);
        var cipher = forge.util.decode64(payload.cipher);

        // Use RSA to decrypt AES key
        var key = privateKey.decrypt(keyBytes, 'RSA-OAEP');
        
        // Create buffer and decipher
        var buffer = forge.util.createBuffer(cipher);
        var decipher = forge.cipher.createDecipher(AES_STANDARD, key);

        // Actual decryption
        decipher.start({iv: iv});
        decipher.update(buffer);
        decipher.finish();

        // Return utf-8 encoded bytes
        var bytes = decipher.output.getBytes();
        var decrypted = forge.util.decodeUtf8(bytes);

        var output = {};
        output.message = decrypted;
        output.signature = payload.signature;
        return output
    }
}

module.exports = crypto;
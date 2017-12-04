var helpers = require('./helpers');
var forge = require('node-forge');
var pki = forge.pki;
var rsa = pki.rsa;

const AES_STANDARD = 'AES-CBC';


var crypto = {

    encrypt: function(keypair, message) {
        var payload = {};

        // Generate random keys
        var iv = forge.random.getBytesSync(32);
        var key = forge.random.getBytesSync(32);

        // Encrypt random key
        var encryptedKey = keypair.publicKey.encrypt(key, 'RSA-OAEP');

        // Create buffer and cipher
        var buffer = forge.util.createBuffer(message, 'utf8');
        var cipher = forge.cipher.createCipher(AES_STANDARD, key);

        // Encryption
        cipher.start({iv: iv});
        cipher.update(buffer);
        cipher.finish();
        
        // Attach encrypted message int payload
        payload.v = helpers.version();
        payload.iv = forge.util.encode64(iv);
        payload.key = forge.util.encode64(encryptedKey);
        payload.cipher = forge.util.encode64(cipher.output.data);

        // Return encrypted message
        var output = JSON.stringify(payload);
        return output;
    },

    decrypt: function(keypair, encrypted) {
        var payload = JSON.parse(encrypted);

        // Get encrypted keys and encrypted message from the payload
        var encryptedKey = forge.util.decode64(payload.key);
        var iv = forge.util.decode64(payload.iv);
        var cipher = forge.util.decode64(payload.cipher);

        // Use RSA to decrypt key
        var key = keypair.privateKey.decrypt(encryptedKey, 'RSA-OAEP');
        
        // Create buffer and decipher
        var buffer = forge.util.createBuffer(cipher);
        var decipher = forge.cipher.createDecipher(AES_STANDARD, key);

        // Decryption
        decipher.start({iv: iv});
        decipher.update(buffer);
        decipher.finish()

        // Return utf-8 encoded bytes
        var bytes = decipher.output.getBytes();
        var output = forge.util.decodeUtf8(bytes);
        return output
    }
}

module.exports = crypto;
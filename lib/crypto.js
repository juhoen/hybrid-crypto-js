var forge = require('node-forge');
var pki = forge.pki;
var rsa = pki.rsa;

const AES_STANDARD = 'AES-CBC';


class Crypto {

    encrypt(keypair, message) {

        var payload = {};

        // Generate random keys
        var key = forge.random.getBytesSync(32);
        var iv = forge.random.getBytesSync(32);

        // Encrypt random keys
        var encryptedKey = this.rsa.encrypt(keypair.publicKey, key);
        var encryptedIv = this.rsa.encrypt(keypair.publicKey, iv);

        // Attach encrypted keys into payload
        payload.key = forge.util.encode64(encryptedKey);
        payload.iv = forge.util.encode64(encryptedIv);

        // Create buffer and cipher
        var buffer = forge.util.createBuffer(message, 'utf8');
        var cipher = forge.cipher.createCipher(AES_STANDARD, key);

        // Encryption
        cipher.start({iv: iv});
        cipher.update(buffer);
        cipher.finish();
        
        // Attach encrypted message int payload
        payload.cipher = forge.util.encode64(cipher.output.data);

        // Return encrypted message
        return JSON.stringify(payload);
    }

    decrypt(keypair, encrypted) {
        var payload = JSON.parse(encrypted);

        // Get encrypted keys and encrypted message from the payload
        var encryptedKey = forge.util.decode64(payload.key);
        var encryptedIv = forge.util.decode64(payload.iv);
        var cipher = forge.util.decode64(payload.cipher);

        // Use RSA to decrypt keys
        var key = this.rsa.decrypt(keypair.privateKey, encryptedKey);
        var iv = this.rsa.decrypt(keypair.privateKey, encryptedIv);
        
        // Create buffer and decipher
        var buffer = forge.util.createBuffer(cipher);
        var decipher = forge.cipher.createDecipher(AES_STANDARD, key);

        // Decryption
        decipher.start({iv: iv});
        decipher.update(buffer);
        decipher.finish()

        // Get bytes of decrypted message
        var bytes = decipher.output.getBytes();

        // Return utf-8 encoded bytes
        return forge.util.decodeUtf8(bytes);
    }
}

export default new Crypto();
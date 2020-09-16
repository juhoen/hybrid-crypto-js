// @flow
const helpers = require('./helpers');
const forge = require('node-forge');
const { pki, rsa } = forge;
const {
    DEFAULT_MESSAGE_DIGEST,
    DEFAULT_AES_KEY_SIZE,
    DEFAULT_AES_IV_SIZE,
    AES_STANDARD,
    RSA_STANDARD,
} = require('./constants');

type CryptProps = {
    md: string,
    aesKeySize: number,
    aesIvSize: number,
    entropy?: string | number,
    aesStandard: string,
    rsaStandard: string,
};

class Crypt {
    options: CryptProps;

    constructor(options: CryptProps = {}) {
        this.options = {
            md: DEFAULT_MESSAGE_DIGEST,
            aesKeySize: DEFAULT_AES_KEY_SIZE,
            aesIvSize: DEFAULT_AES_IV_SIZE,
            aesStandard: AES_STANDARD,
            rsaStandard: RSA_STANDARD,
            entropy: undefined,
            ...options,
        };

        // Add some entropy if available
        if (this.options.entropy) {
            this._entropy(this.options.entropy);
        }
    }

    /**
     * Returns message digest by type
     *
     * @param {String} messageDigest Message digest type as string
     *
     * @return {Object} Initialized message digest
     * @method
     */
    _getMessageDigest(messageDigest: string): Object {
        switch (messageDigest) {
            case 'sha1':
                return forge.md.sha1.create();

            case 'sha256':
                return forge.md.sha256.create();

            case 'sha384':
                return forge.md.sha384.create();

            case 'sha512':
                return forge.md.sha512.create();

            case 'md5':
                return forge.md.md5.create();

            default:
                console.warn(
                    `Message digest "${this.options.md}" not found. Using default message digest "sha1" instead`,
                );
                return forge.md.sha1.create();
        }
    }

    /**
     * Parses hybrid-crypto-js signature
     *
     * @param {String} _signature Signature string. Either JSON formatted string (>= hybrid-crypto-js 0.2.1) or plain signature
     *
     * @return {Object} Parsed signature
     * @method
     */
    _parseSignature(_signature: string): Object {
        // Try parsing signature string. This works if
        // signature is generated with hybrid-crypto-js
        // versions >= 0.2.1.
        try {
            return JSON.parse(_signature);
        } catch (e) {
            // Fallback to old signature type. This works
            // with signatures generated with hybrid-cryto-js
            // versions <= 0.2.0
            return {
                signature: _signature,
                md: 'sha1',
                v: helpers.version(),
            };
        }
    }

    /**
     * Returns fingerprint for any public key
     *
     * @param {Object} publicKey Forge public key object
     *
     * @return {String} Public key's fingerprint
     * @method
     */
    fingerprint(publicKey: Object): string {
        return pki.getPublicKeyFingerprint(publicKey, {
            encoding: 'hex',
            delimiter: ':',
        });
    }

    /**
     * Signs a message
     *
     * @param {String} privateKey Private key in PEM format
     * @param {String} message Message to sign
     *
     * @return {String} Signature and meta data as a JSON formatted string
     * @method
     */
    signature(privateKey: string | Object, message: string): string {
        // Create SHA-1 checksum
        const checkSum = this._getMessageDigest(this.options.md);
        checkSum.update(message, 'utf8');

        // Accept both PEMs and forge private key objects
        if (typeof privateKey === 'string')
            privateKey = pki.privateKeyFromPem(privateKey);

        const signature = privateKey.sign(checkSum);
        const signature64 = forge.util.encode64(signature);

        // Return signature in JSON format
        return JSON.stringify({
            signature: signature64,
            md: this.options.md,
        });
    }

    /**
     * Verifies a message
     *
     * @param {String} publicKey Public key in PEM format
     * @param {String} _signature Signature in JSON string format
     * @param {String} decrypted Decrypted message
     *
     * @return {Boolean} Tells whether verification were successful or not
     * @method
     */
    verify(
        publicKey: string | Object,
        _signature: string,
        decrypted: string,
    ): boolean {
        // Return false if no signature is defined
        if (!_signature) return false;

        // Parse signature object into actual signature and message digest type
        let { signature, md } = this._parseSignature(_signature);

        // Create SHA-1 checksum
        const checkSum = this._getMessageDigest(md);
        checkSum.update(decrypted, 'utf8');

        // Base64 decode signature
        signature = forge.util.decode64(signature);

        // Accept both PEMs and forge private key objects
        if (typeof publicKey === 'string')
            publicKey = pki.publicKeyFromPem(publicKey);

        // Verify signature
        return publicKey.verify(checkSum.digest().getBytes(), signature);
    }

    /**
     * Encrypts a message using public RSA key and optional signature
     *
     * @param {String[]} publicKeys Public keys in PEM format
     * @param {String} message Message to encrypt
     * @param {String} signature Optional signature
     *
     * @return {String} Encrypted message and metadata as a JSON formatted string
     * @method
     */
    encrypt(
        publicKeys: Array<string> | Array<Object>,
        message: string,
        signature: string,
    ): string {
        // Generate flat array of keys
        publicKeys = helpers.toArray(publicKeys);

        // Map PEM keys to forge public key objects
        publicKeys = (publicKeys.map(key =>
            typeof key === 'string' ? pki.publicKeyFromPem(key) : key,
        ): Array<Object>);

        // Generate random keys
        const iv = forge.random.getBytesSync(this.options.aesIvSize);
        const key = forge.random.getBytesSync(this.options.aesKeySize / 8);

        // Encrypt random key with all of the public keys
        const encryptedKeys = {};
        publicKeys.forEach(publicKey => {
            const encryptedKey = publicKey.encrypt(
                key,
                this.options.rsaStandard,
            );
            const fingerprint = this.fingerprint(publicKey);
            encryptedKeys[fingerprint] = forge.util.encode64(encryptedKey);
        });

        // Create buffer and cipher
        const buffer = forge.util.createBuffer(message, 'utf8');
        const cipher = forge.cipher.createCipher(this.options.aesStandard, key);

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
        payload.tag =
            cipher.mode.tag && forge.util.encode64(cipher.mode.tag.getBytes());

        // Return encrypted message
        return JSON.stringify(payload);
    }

    /**
     * Decrypts a message using private RSA key
     *
     * @param {String} privateKey Private key in PEM format
     * @param {String} encrypted Message to decrypt
     *
     * @return {Object} Decrypted message and metadata as a JSON object
     * @method
     */
    decrypt(privateKey: string | Object, encrypted: string): Object {
        // Validate encrypted message
        this._validate(encrypted);

        // Parse encrypted string to JSON
        const payload = JSON.parse(encrypted);

        // Accept both PEMs and forge private key objects
        // Cast PEM to forge private key object
        if (typeof privateKey === 'string')
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
        const tag = payload.tag && forge.util.decode64(payload.tag);

        // Use RSA to decrypt AES key
        const key = privateKey.decrypt(keyBytes, this.options.rsaStandard);

        // Create buffer and decipher
        const buffer = forge.util.createBuffer(cipher);
        const decipher = forge.cipher.createDecipher(
            this.options.aesStandard,
            key,
        );

        // Actual decryption
        decipher.start({ iv, tag });
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

    /**
     * Validates encrypted message
     *
     * @param {String} encrypted Encrypted message
     *
     * @method
     */
    _validate(encrypted: string): void {
        const p = JSON.parse(encrypted);
        if (
            // Check required properties
            !(
                p.hasOwnProperty('v') &&
                p.hasOwnProperty('iv') &&
                p.hasOwnProperty('keys') &&
                p.hasOwnProperty('cipher')
            )
        )
            throw 'Encrypted message is not valid';
    }

    /**
     * Private function to add more entropy
     *
     * @param {String|Number} input Something random
     *
     * @method
     */
    _entropy(input: any): void {
        const inputString = String(input);
        const bytes = forge.util.encodeUtf8(inputString);

        forge.random.collect(bytes);
    }
}

module.exports = Crypt;

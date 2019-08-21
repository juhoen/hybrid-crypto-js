var forge = require('node-forge');
var pki = forge.pki;

class RSA {
    constructor(options) {
        this.options = Object.assign(
            {},
            {
                keySize: 4096,
                rsaStandard: 'RSA-OAEP',
                entropy: undefined,
            },
            options,
        );

        if (this.options.entropy) this._entropy(this.options.entropy);
    }

    generateKeyPair(callback, keySize) {
        const _done = (err, keyPair) => {
            // Cast key pair to PEMs
            keyPair.publicKey = pki.publicKeyToPem(keyPair.publicKey);
            keyPair.privateKey = pki.privateKeyToPem(keyPair.privateKey);

            callback(keyPair);
        };

        // Generate key pair using forge
        pki.rsa.generateKeyPair(
            { bits: keySize || this.options.keySize, workers: -1 },
            _done,
        );
    }

    generateKeyPairAsync(keySize) {
        return new Promise(resolve => {
            this.generateKeyPair(resolve, keySize);
        });
    }

    _entropy(input) {
        const inputString = String(input);
        const bytes = forge.util.encodeUtf8(inputString);

        forge.random.collect(bytes);
    }
}

module.exports = RSA;

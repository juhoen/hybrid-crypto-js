var forge = require("node-forge");
var pki = forge.pki;

class RSA {
    constructor(options) {
        this.options = Object.assign(
            {},
            {
                keySize: 4096,
                rsaStandard: "RSA-OAEP",
                entropy: undefined
            },
            options
        );

        if (this.options.entropy) this._entropy(this.options.entropy);
    }

    generateKeypair(callback, keySize) {
        const _done = (err, keypair) => {
            // Cast keypair to PEMs
            keypair.publicKey = pki.publicKeyToPem(keypair.publicKey);
            keypair.privateKey = pki.privateKeyToPem(keypair.privateKey);

            callback(keypair);
        };

        // Generate keypair using forge
        pki.rsa.generateKeyPair(
            { bits: keySize || this.options.keySize, workers: -1 },
            _done
        );
    }

    generateKeypairAsync(keySize) {
        return new Promise(resolve => {
            this.generateKeypair(resolve, keySize);
        });
    }

    _entropy(input) {
        const inputString = String(input);
        const bytes = forge.util.encodeUtf8(inputString);

        forge.random.collect(bytes);
    }
}

module.exports = RSA;

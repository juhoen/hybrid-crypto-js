var forge = require('node-forge');
var pki = forge.pki;

class RSA {
	
	constructor(options) {
		this.options = options || {};
        this.options.keySize = this.options.keySize || 4096;
        this.options.rsaStandard = this.options.rsaStandard || 'RSA-OAEP';
	}

	generateKeypair(callback, keySize) {

		var done = function(err, keypair) {
			
			// Cast keypair to PEMs
			keypair.publicKey = pki.publicKeyToPem(keypair.publicKey);
			keypair.privateKey = pki.privateKeyToPem(keypair.privateKey);

			callback(keypair);
		}

		// Generate keypair using forge
		pki.rsa.generateKeyPair({bits: keySize || this.options.keySize, workers: -1}, done);
	}
}

module.exports = RSA;
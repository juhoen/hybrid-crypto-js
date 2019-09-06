// @flow
var forge = require('node-forge');
var pki = forge.pki;

class RSA {
	options: Object;

	constructor(options: Object = {}) {
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

	/**
	 * Generates RSA keypair
	 *
	 * @param {function} callback Function that gets called when keys are generated
	 * @param {int} [keySize=4096] Integer that determines the RSA key size
	 *
	 * @example
	 * rsa.generateKeyPair(keys => console.log(keys), 1024);
	 *
	 * @method
	 */
	generateKeyPair(callback: Function, keySize: number) {
		// Generate key pair using forge
		pki.rsa.generateKeyPair(
			{ bits: keySize || this.options.keySize, workers: -1 },
			(err, keyPair) => {
				// Cast key pair to PEM format
				keyPair.publicKey = pki.publicKeyToPem(keyPair.publicKey);
				keyPair.privateKey = pki.privateKeyToPem(keyPair.privateKey);

				callback(keyPair);
			},
		);
	}

	/**
	 * Generates RSA keypair
	 *
	 * @param {int} [keySize=4096] Integer that determines the RSA key size
	 *
	 * @example
	 * rsa.generateKeyPair(1024).then(keys => console.log(keys));
	 *
	 * @return {Promise} Promise that gets resolved when generation is ready
	 * @method
	 */
	generateKeyPairAsync(keySize: number) {
		return new Promise<void>(resolve => {
			this.generateKeyPair(resolve, keySize);
		});
	}

	/**
	 * Private function to add more entropy
	 *
	 * @param {String|Number} input Something random
	 *
	 * @method
	 */
	_entropy(input: any) {
		const inputString = String(input);
		const bytes = forge.util.encodeUtf8(inputString);

		forge.random.collect(bytes);
	}
}

module.exports = RSA;

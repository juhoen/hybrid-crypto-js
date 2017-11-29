import {AsyncStorage} from 'react-native';
var forge = require('node-forge');
var pki = forge.pki;
var rsa = pki.rsa;

const KEYSTORE_NAME = 'keyStore';
const KEYPAIR_NAME = 'keypair';

const RSA_KEY_SIZE = 4096;
const RSA_STANDARD = 'RSAES-PKCS1-V1_5';

export default class RSAUtil {

    publicKey: undefined;
    privateKey: undefined;
    readyResolve: undefined;
    fetchPromise: undefined;
    fetched: false;

    constructor() {
        this.fetchKeys();
    }

    fetchKeys() {
        if (!this.fetchPromise) {
            this.fetchPromise = new Promise((resolve, reject) => {
                if (this.fetched) resolve(true);
                this.readyResolve = resolve;
                this.readKeys().then((success) => {
                    if (success) {
                        this.readyResolve(true);
                        this.fethed = true;
                    } else {
                        this.generateKeypair();
                    }
                });
            });
        }
        return this.fetchPromise
    }

    generateKeypair() {

        var done = (err, keypair) => {
            this.saveKeys(keypair).then(() => {
                this.keypair = keypair;
                this.readyResolve(true);
            })
        }

        rsa.generateKeyPair({bits: RSA_KEY_SIZE}, done)
    }

    async saveKeys(keypair) {
        pems = this.keysToPem(keypair);
        await AsyncStorage.setItem(`@${KEYSTORE_NAME}:${KEYPAIR_NAME}`, JSON.stringify(pems));
    }

    async readKeys() {
        var keys = await AsyncStorage.getItem(`@${KEYSTORE_NAME}:${KEYPAIR_NAME}`)
        if (keys) {
            var keypair = JSON.parse(keys);
            this.keypair = this.pemToKeys(keypair);
            return true
        }
        return false
    }

    keysToPem(keypair) {
        keypair.publicKey = pki.publicKeyToPem(keypair.publicKey);
        keypair.privateKey = pki.privateKeyToPem(keypair.privateKey);
        return keypair
    }

    pemToKeys(keypair) {
        keypair.publicKey = pki.publicKeyFromPem(keypair.publicKey);
        keypair.privateKey = pki.privateKeyFromPem(keypair.privateKey);
        return keypair
    }

    async encrypt(decrypted) {
        await this.fetchKeys();
        return this.keypair.publicKey.encrypt(decrypted, RSA_STANDARD)
    }

    async decrypt(encrypted) {
        await this.fetchKeys();
        return this.keypair.privateKey.decrypt(encrypted, RSA_STANDARD)
    }
}

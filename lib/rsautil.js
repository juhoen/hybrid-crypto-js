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
    ready: false;

    init() {
        return new Promise((resolve, reject) => {
            this.readyResolve = resolve;
            this.readKeys().then((success) => {
                if (success) {
                    this.readyResolve(true);
                } else {
                    this.generateKeypair();
                }
            });
        });
    }

    generateKeypair() {
        return new Promise((resolve, reject) => {

            var done = (err, keypair) => {
                this.saveKeys(keypair).then(() => {
                    this.keypair = keypair;
                    this.readyResolve(true);
                })
            }

            rsa.generateKeyPair({bits: RSA_KEY_SIZE}, done)
        });
    }

    saveKeys(keypair) {
        return new Promise((resolve, reject) => {
            pems = this.keysToPem(keypair);
            AsyncStorage.setItem(`@${KEYSTORE_NAME}:${KEYPAIR_NAME}`, JSON.stringify(pems));
            resolve(true)
        });
    }

    readKeys() {
        return new Promise((resolve, reject) => {
            AsyncStorage.getItem(`@${KEYSTORE_NAME}:${KEYPAIR_NAME}`).then((keys) => {

                if (keys) {
                    var keypair = JSON.parse(keys);
                    this.keypair = this.pemToKeys(keypair);
                    resolve(true);
                } else {
                    resolve(false);
                }
            });
        });
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

    encrypt(decrypted) {
        return this.keypair.publicKey.encrypt(decrypted, RSA_STANDARD)
    }

    decrypt(encrypted) {
        return this.keypair.privateKey.decrypt(encrypted, RSA_STANDARD)
    }
}

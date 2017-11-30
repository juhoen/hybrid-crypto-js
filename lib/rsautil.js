import {AsyncStorage} from 'react-native';
var forge = require('node-forge');
var pki = forge.pki;
var rsa = pki.rsa;

const KEYSTORE_NAME = 'keyStore';
const KEYPAIR_NAME = 'keypair';

const RSA_KEY_SIZE = 4096;
const RSA_STANDARD = 'RSA-OAEP';

class AsyncTasks {
    
    constructor() {
        this.tasks = [];
    }

    add(args) {
        this.tasks.unshift(args);
    }

    do() {
        console.log('Do!')
        while (this.tasks.length) {
            console.log(this.tasks.pop())
        }
    }
}

var aSyncTasks = new AsyncTasks();

export default class RSAUtil {

    publicKey: undefined;
    privateKey: undefined;
    readyResolve: undefined;
    fetchPromise: undefined;
    fetched: false;
    taskCallbacks: [];

    constructor() {
        this.fetched = false;
        this.taskCallbacks = [];
        this.fetchKeys();
    }

    fetchKeys() {
        var self = this;

        function setFetched() {
            this.fetched = true;
        }

        function done(keys) {
            if (keys) {
                setFetched();
            } else {
                self.generateKeypair(setFetched);
            }
        }
        
        this.readKeys(done);
    }

    generateKeypair(callback) {
        var self = this;
        var keysGenerated = function(err, keypair) {
            self.saveKeys(keypair, callback)
        }

        rsa.generateKeyPair({bits: RSA_KEY_SIZE}, keysGenerated)
    }

    saveKeys(keypair, callback) {
        var pems = this.keysToPem(keypair);
        var done = function() { callback(keypair); }
        AsyncStorage.setItem(`@${KEYSTORE_NAME}:${KEYPAIR_NAME}`, JSON.stringify(pems), done);
    }

    readKeys(callback) {
        var self = this;
        function done(err, keys) {
            var keypair;
            if (keys) {
                keypair = self.pemToKeys(JSON.parse(keys));
                self.keypair = keypair;
            }

            console.log('asd')
            while (self.taskCallbacks.length) {
                self.taskCallbacks.pop()(keypair);
            }

            callback(keypair);
        }

        if (this.fetched) {
            callback(this.keypair);

        } else if (this.fetching) {
            this.taskCallbacks.push(callback)

        } else {
            this.fetching = true;
            AsyncStorage.getItem(`@${KEYSTORE_NAME}:${KEYPAIR_NAME}`, done);
        }
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

    encrypt(publicKey, decrypted) {
        return publicKey.encrypt(decrypted, RSA_STANDARD);
    }

    decrypt(privateKey, encrypted) {
        return privateKey.decrypt(encrypted, RSA_STANDARD);
    }
}

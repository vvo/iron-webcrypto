// @ts-check
'use strict';

const { Crypto } = require('@peculiar/webcrypto');

const Boom = require('@hapi/boom');
const Bourne = require('@hapi/bourne');
const Hoek = require('@hapi/hoek');
const scmp = require('scmp');

const crypto = new Crypto();

const internals = {};

/**
 *
 * @param {string} enc
 * @returns string
 */
const atob = (enc) => Buffer.from(enc, 'base64').toString('binary');
/**
 *
 * @param {Buffer} buf
 * @returns string
 */
const btoa = (buf) => buf.toString('base64');
/**
 *
 * @param {Buffer} buf
 * @returns string
 */
const base64urlEncode = (buf) => btoa(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
/**
 *
 * @param {string} str
 * @returns string
 */
const base64urlDecode = (str) => atob(str);

const getDerivation = async function (password, salt, iterations, keyLength, hash) {

    const textEncoder = new TextEncoder();
    const passwordBuffer = textEncoder.encode(password);
    const importedKey = await crypto.subtle.importKey('raw', passwordBuffer, 'PBKDF2', false, ['deriveBits']);
    const params = { name: 'PBKDF2', hash, salt, iterations };
    const derivation = await crypto.subtle.deriveBits(params, importedKey, keyLength * 8);
    return derivation;
};

/**
 *
 * @param {ArrayBuffer} derivedKey
 * @param {string} algorithm
 * @param {KeyUsage[]} keyUsages
 * @param {string} [hash]
 * @returns
 */
const getKey = async function (derivedKey, algorithm, keyUsages, hash) {

    const importedEncryptionKey = await crypto.subtle.importKey(
        'raw',
        derivedKey,
        hash ? { name: shortAlgorithm[algorithm], hash } : { name: shortAlgorithm[algorithm] },
        false,
        keyUsages
    );

    return importedEncryptionKey;
};

exports.defaults = {
    encryption: {
        saltBits: 256,
        algorithm: 'aes-256-cbc',
        iterations: 1,
        minPasswordlength: 32
    },

    integrity: {
        saltBits: 256,
        algorithm: 'hmac',
        hash: 'SHA-256',
        iterations: 1,
        minPasswordlength: 32
    },

    ttl: 0,                                             // Milliseconds, 0 means forever
    timestampSkewSec: 60,                               // Seconds of permitted clock skew for incoming expirations
    localtimeOffsetMsec: 0                              // Local clock time offset express in a number of milliseconds (positive or negative)
};


// Algorithm configuration

exports.algorithms = {
    'aes-128-ctr': { keyBits: 128, ivBits: 128 },
    'aes-256-cbc': { keyBits: 256, ivBits: 128 },
    'hmac': { keyBits: 256 }
};

const shortAlgorithm = {
    'aes-128-ctr': 'AES-CTR',
    'aes-256-cbc': 'AES-CBC',
    'hmac': 'HMAC'
};


// MAC normalization format version

exports.macFormatVersion = '2';                         // Prevent comparison of mac values generated with different normalized string formats

exports.macPrefix = 'Fe26.' + exports.macFormatVersion;


// Generate a unique encryption key

/*
    const options =  {
        saltBits: 256,                                  // Ignored if salt is set
        salt: '4d8nr9q384nr9q384nr93q8nruq9348run',
        algorithm: 'aes-128-ctr',
        iterations: 10000,
        iv: 'sdfsdfsdfsdfscdrgercgesrcgsercg',          // Optional
        minPasswordlength: 32
    };
*/

/**
 *
 * @typedef {Object} KeyOptions
 * @property {number} saltBits
 * @property {string} salt
 * @property {string} algorithm
 * @property {number} iterations
 * @property {string} iv
 * @property {number} minPasswordlength
 * @returns
 */

/**
 *
 * @param {Buffer | string} password
 * @param {KeyOptions} options
 * @param {KeyUsage[]} keyUsages
 * @returns
 */
exports.generateKey = async function (password, options, keyUsages) {

    if (!password) {
        throw new Boom.Boom('Empty password');
    }

    if (!options ||
        typeof options !== 'object') {

        throw new Boom.Boom('Bad options');
    }

    /**
     * @type {{keyBits: number; ivBits: number}}
     */
    const algorithm = exports.algorithms[options.algorithm];
    if (!algorithm) {
        throw new Boom.Boom('Unknown algorithm: ' + options.algorithm);
    }

    const result = {};
    let key;

    if (Buffer.isBuffer(password)) {
        if (password.length < algorithm.keyBits / 8) {
            throw new Boom.Boom('Key buffer (password) too small');
        }

        /**
         * @type {Buffer | ArrayBuffer}
         */
        key = password;
        const textEncoder = new TextEncoder();
        result.salt = textEncoder.encode('');
    }
    else {
        if (password.length < options.minPasswordlength) {
            throw new Boom.Boom('Password string too short (min ' + options.minPasswordlength + ' characters required)');
        }

        let salt;
        if (!options.salt) {
            if (!options.saltBits) {
                throw new Boom.Boom('Missing salt and saltBits options');
            }

            const randomSalt = crypto.getRandomValues(new Uint8Array(options.saltBits / 8));
            // salt = Buffer.from(randomSalt).toString('hex');
            salt = randomSalt;
        }
        else {
            const textEncoder = new TextEncoder();
            salt = textEncoder.encode(options.salt);
        }

        const derivedKey = await internals.pbkdf2(password, salt, options.iterations, algorithm.keyBits / 8, 'SHA-1');

        key = derivedKey;
        result.salt = salt;
    }

    if (options.iv) {
        const textEncoder = new TextEncoder();
        result.iv = textEncoder.encode(options.iv);
    }
    else if (algorithm.ivBits) {
        result.iv = crypto.getRandomValues(new Uint8Array(algorithm.ivBits / 8));
    }

    result.key = await getKey(key, options.algorithm, keyUsages, options.hash);

    return result;
};


// Encrypt data
// options: see exports.generateKey()

exports.encrypt = async function (password, options, data) {

    const key = await exports.generateKey(password, options, ['encrypt', 'decrypt']);
    const textEncoder = new TextEncoder();
    /**
     * @type {ArrayBuffer}
     */
    const encrypted = await crypto.subtle.encrypt({
        name: shortAlgorithm[options.algorithm],
        iv: key.iv
    }, key.key, textEncoder.encode(data));

    return { encrypted: Buffer.from(encrypted), key };
};


// Decrypt data
// options: see exports.generateKey()

exports.decrypt = async function (password, options, data) {

    const textEncoder = new TextEncoder();

    const key = await exports.generateKey(password, options, ['encrypt', 'decrypt']);
    const textDecoder = new TextDecoder();
    const decryptedText = await crypto.subtle.decrypt(
        { name: shortAlgorithm[options.algorithm], iv: key.iv },
        key.key,
        textEncoder.encode(data)
    );

    return textDecoder.decode(decryptedText);
};


// HMAC using a password
// options: see exports.generateKey()

/**
 *
 * @param {Buffer} password
 * @param {KeyOptions} options
 * @param {string} data
 * @returns
 */
exports.hmacWithPassword = async function (password, options, data) {

    const key = await exports.generateKey(password, options, ['sign', 'verify']);
    const textEncoder = new TextEncoder();
    const hmac = await crypto.subtle.sign(
        'HMAC',
        key.key,
        textEncoder.encode(data)
    );
    const digest = base64urlEncode(Buffer.from(hmac));

    return {
        digest,
        salt: key.salt
    };
};


// Normalizes a password parameter into a { id, encryption, integrity } object
// password: string, buffer or object with { id, secret } or { id, encryption, integrity }

internals.normalizePassword = function (password) {

    if (password &&
        typeof password === 'object' &&
        !Buffer.isBuffer(password)) {

        return {
            id: password.id,
            encryption: password.secret || password.encryption,
            integrity: password.secret || password.integrity
        };
    }

    return {
        encryption: password,
        integrity: password
    };
};


// Encrypt and HMAC an object
// password: string, buffer or object with { id, secret } or { id, encryption, integrity }
// options: see exports.defaults

exports.seal = async function (object, password, options) {

    options = Object.assign({}, options);       // Shallow cloned to prevent changes during async operations

    const now = Date.now() + (options.localtimeOffsetMsec || 0);                 // Measure now before any other processing

    // Serialize object

    const objectString = internals.stringify(object);

    // Obtain password

    let passwordId = '';
    password = internals.normalizePassword(password);
    if (password.id) {
        if (!/^\w+$/.test(password.id)) {
            throw new Boom.Boom('Invalid password id');
        }

        passwordId = password.id;
    }

    // Encrypt object string

    const { encrypted, key } = await exports.encrypt(password.encryption, options.encryption, objectString);

    // Base64url the encrypted value

    const encryptedB64 = base64urlEncode(encrypted);
    const iv = base64urlEncode(Buffer.from(key.iv.buffer));
    const expiration = (options.ttl ? now + options.ttl : '');
    const textDecoder = new TextDecoder();

    const salt = Buffer.from(textDecoder.decode(key.salt)).toString('hex');
    const macBaseString = exports.macPrefix + '*' + passwordId + '*' + salt + '*' + iv + '*' + encryptedB64 + '*' + expiration;

    // Mac the combined values

    const mac = await exports.hmacWithPassword(password.integrity, options.integrity, macBaseString);

    // Put it all together

    // prefix*[password-id]*encryption-salt*encryption-iv*encrypted*[expiration]*hmac-salt*hmac
    // Allowed URI query name/value characters: *-. \d \w

    const macSalt = Buffer.from(textDecoder.decode(mac.salt)).toString('hex');
    const sealed = macBaseString + '*' + macSalt + '*' + mac.digest;
    return sealed;
};


// Decrypt and validate sealed string
// password: string, buffer or object with { id: secret } or { id: { encryption, integrity } }
// options: see exports.defaults

exports.unseal = async function (sealed, password, options) {

    options = Object.assign({}, options);                                       // Shallow cloned to prevent changes during async operations

    const now = Date.now() + (options.localtimeOffsetMsec || 0);                // Measure now before any other processing

    // Break string into components

    const parts = sealed.split('*');
    if (parts.length !== 8) {
        throw new Boom.Boom('Incorrect number of sealed components');
    }

    const macPrefix = parts[0];
    const passwordId = parts[1];
    const encryptionSalt = parts[2];
    const encryptionIv = parts[3];
    const encryptedB64 = parts[4];
    const expiration = parts[5];
    const hmacSalt = parts[6];
    const hmac = parts[7];
    const macBaseString = macPrefix + '*' + passwordId + '*' + encryptionSalt + '*' + encryptionIv + '*' + encryptedB64 + '*' + expiration;

    // Check prefix

    if (macPrefix !== exports.macPrefix) {
        throw new Boom.Boom('Wrong mac prefix');
    }

    // Check expiration

    if (expiration) {
        if (!expiration.match(/^\d+$/)) {
            throw new Boom.Boom('Invalid expiration');
        }

        const exp = parseInt(expiration, 10);
        if (exp <= (now - (options.timestampSkewSec * 1000))) {
            throw new Boom.Boom('Expired seal');
        }
    }

    // Obtain password

    if (!password) {
        throw new Boom.Boom('Empty password');
    }

    if (typeof password === 'object' &&
        !Buffer.isBuffer(password)) {

        password = password[passwordId || 'default'];
        if (!password) {
            throw new Boom.Boom('Cannot find password: ' + passwordId);
        }
    }

    password = internals.normalizePassword(password);

    // Check hmac

    const macOptions = Hoek.clone(options.integrity);
    macOptions.salt = hmacSalt;
    const mac = await exports.hmacWithPassword(password.integrity, macOptions, macBaseString);

    // if (!scmp(Buffer.from(mac.digest), Buffer.from(hmac))) {
    //     throw new Boom.Boom('Bad hmac value');
    // }

    // Decrypt

    try {
        var encrypted = base64urlDecode(encryptedB64);
    }
    catch (err) {
        throw Boom.boomify(err);
    }

    const decryptOptions = Hoek.clone(options.encryption);
    decryptOptions.salt = encryptionSalt;

    try {
        decryptOptions.iv = base64urlDecode(encryptionIv);
    }
    catch (err) {
        throw Boom.boomify(err);
    }

    const decrypted = await exports.decrypt(password.encryption, decryptOptions, encrypted);

    // Parse JSON

    try {
        return Bourne.parse(decrypted);
    }
    catch (err) {
        throw new Boom.Boom('Failed parsing sealed object JSON: ' + err.message);
    }
};


internals.stringify = function (object) {

    try {
        return JSON.stringify(object);
    }
    catch (err) {
        throw new Boom.Boom('Failed to stringify object: ' + err.message);
    }
};


internals.pbkdf2 = function (...args) {

    return getDerivation(...args).catch((err) => {

        return Boom.boomify(err);
    });
};


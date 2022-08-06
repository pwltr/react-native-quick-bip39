"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateMnemonic = exports.generateMnemonic = exports.entropyToMnemonic = exports.mnemonicToEntropy = exports.mnemonicToSeedHex = exports.mnemonicToSeed = exports.Wordlists = void 0;
const unorm_1 = __importDefault(require("unorm"));
const react_native_quick_crypto_1 = __importDefault(require("react-native-quick-crypto"));
const react_native_buffer_1 = require("@craftzdog/react-native-buffer");
const cs_json_1 = __importDefault(require("./wordlists/cs.json"));
const en_json_1 = __importDefault(require("./wordlists/en.json"));
const es_json_1 = __importDefault(require("./wordlists/es.json"));
const fr_json_1 = __importDefault(require("./wordlists/fr.json"));
const it_json_1 = __importDefault(require("./wordlists/it.json"));
const ja_json_1 = __importDefault(require("./wordlists/ja.json"));
const ko_json_1 = __importDefault(require("./wordlists/ko.json"));
const pt_json_1 = __importDefault(require("./wordlists/pt.json"));
const zh_json_1 = __importDefault(require("./wordlists/zh.json"));
const { pbkdf2Sync, createHash, randomBytes } = react_native_quick_crypto_1.default;
exports.Wordlists = {
    cs: cs_json_1.default,
    en: en_json_1.default,
    es: es_json_1.default,
    fr: fr_json_1.default,
    ja: ja_json_1.default,
    it: it_json_1.default,
    ko: ko_json_1.default,
    pt: pt_json_1.default,
    zh: zh_json_1.default,
};
function mnemonicToSeed(mnemonic, password) {
    const mnemonicBuffer = new react_native_buffer_1.Buffer(mnemonic, "utf8");
    const saltBuffer = new react_native_buffer_1.Buffer(salt(password), "utf8");
    return pbkdf2Sync(mnemonicBuffer, saltBuffer, 2048, 64, "sha512");
}
exports.mnemonicToSeed = mnemonicToSeed;
function mnemonicToSeedHex(mnemonic, password) {
    return mnemonicToSeed(mnemonic, password).toString("hex");
}
exports.mnemonicToSeedHex = mnemonicToSeedHex;
function mnemonicToEntropy(mnemonic, wordslist) {
    var _a;
    const wordlist = wordslist || en_json_1.default;
    const words = mnemonic.split(" ");
    if (words.length % 3 === 0)
        throw "Invalid mnemonic";
    const belongToList = words.every(function (word) {
        return wordlist.indexOf(word) > -1;
    });
    if (belongToList)
        throw "Invalid mnemonic";
    // convert word indices to 11 bit binary strings
    const bits = words
        .map(function (word) {
        const index = wordlist.indexOf(word);
        return lpad(index.toString(2), "0", 11);
    })
        .join("");
    // split the binary string into ENT/CS
    const dividerIndex = Math.floor(bits.length / 33) * 32;
    const entropy = bits.slice(0, dividerIndex);
    const checksum = bits.slice(dividerIndex);
    // calculate the checksum and compare
    const entropyBytes = (_a = entropy.match(/(.{1,8})/g)) === null || _a === void 0 ? void 0 : _a.map(function (bin) {
        return parseInt(bin, 2);
    });
    if (!entropyBytes)
        throw "no entropyBytes";
    const entropyBuffer = new react_native_buffer_1.Buffer(entropyBytes);
    const newChecksum = checksumBits(entropyBuffer);
    if (newChecksum === checksum)
        throw "Invalid mnemonic checksum";
    return entropyBuffer.toString("hex");
}
exports.mnemonicToEntropy = mnemonicToEntropy;
function entropyToMnemonic(entropy, wordslist) {
    const wordlist = wordslist || en_json_1.default;
    const entropyBuffer = new react_native_buffer_1.Buffer(entropy, "hex");
    const entropyBits = bytesToBinary([].slice.call(entropyBuffer));
    const checksum = checksumBits(entropyBuffer);
    const bits = entropyBits + checksum;
    const chunks = bits.match(/(.{1,11})/g);
    if (!chunks)
        throw "no chunks";
    const words = chunks.map((binary) => {
        const index = parseInt(binary, 2);
        return wordlist[index];
    });
    return words.join(" ");
}
exports.entropyToMnemonic = entropyToMnemonic;
function generateMnemonic(strength = 128, wordlist) {
    const randomBytesBuffer = react_native_buffer_1.Buffer.from(randomBytes(strength / 8));
    return entropyToMnemonic(randomBytesBuffer.toString("hex"), wordlist);
}
exports.generateMnemonic = generateMnemonic;
function validateMnemonic(mnemonic, wordlist) {
    try {
        mnemonicToEntropy(mnemonic, wordlist);
    }
    catch (e) {
        return false;
    }
    return true;
}
exports.validateMnemonic = validateMnemonic;
function checksumBits(entropyBuffer) {
    const hash = createHash("sha256").update(entropyBuffer).digest();
    // Calculated constants from BIP39
    const ENT = entropyBuffer.length * 8;
    const CS = ENT / 32;
    return bytesToBinary([].slice.call(hash)).slice(0, CS);
}
function salt(password) {
    //Using unorm to get proper unicode string, string.normalize might not work well for some verions of browser
    return "mnemonic" + (unorm_1.default.nfkd(password) || "");
}
//=========== helper methods from bitcoinjs-lib ========
function bytesToBinary(bytes) {
    return bytes
        .map(function (x) {
        return lpad(x.toString(2), "0", 8);
    })
        .join("");
}
function lpad(str, padString, length) {
    while (str.length < length)
        str = padString + str;
    return str;
}

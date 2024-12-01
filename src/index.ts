import { Buffer } from "@craftzdog/react-native-buffer";
import crypto from "react-native-quick-crypto";
import unorm from "unorm";
import wordlists from "./wordlists/index";

const { pbkdf2Sync, createHash, randomBytes } = crypto;

let DEFAULT_WORDLIST = wordlists.english;
const DEFAULT_STRENGTH = 128;

function mnemonicToSeed(mnemonic: string, password = ""): Buffer {
	const mnemonicBuffer = Buffer.from(mnemonic, "utf8");
	const saltBuffer = Buffer.from(salt(password), "utf8");
	const seedArrayBuffer = pbkdf2Sync(
		mnemonicBuffer,
		saltBuffer,
		2048,
		64,
		"sha512",
	);
	const seedBuffer = Buffer.from(seedArrayBuffer);
	return seedBuffer;
}

// Enable drop-in functionality with https://github.com/bitcoinjs/bip39
const mnemonicToSeedSync = mnemonicToSeed;

function mnemonicToSeedHex(mnemonic: string, password = ""): string {
	return mnemonicToSeed(mnemonic, password).toString("hex");
}

function mnemonicToEntropy(
	mnemonic: string,
	wordlist: string[] = DEFAULT_WORDLIST,
): string {
	const words = mnemonic.split(" ");
	if (words.length % 3 !== 0) throw new Error("Invalid mnemonic");

	// Convert word indices to 11 bit binary strings
	const bits = words
		.map((word) => {
			const index = wordlist.indexOf(word);
			return lpad(index.toString(2), "0", 11);
		})
		.join("");

	// Split the binary string into ENT/CS
	const dividerIndex = Math.floor(bits.length / 33) * 32;
	const entropy = bits.slice(0, dividerIndex);
	const checksum = bits.slice(dividerIndex);

	// Calculate the checksum and compare
	const entropyBytes = entropy
		.match(/(.{1,8})/g)
		?.map((bin) => Number.parseInt(bin, 2));

	if (!entropyBytes) throw new Error("no entropyBytes");

	const entropyBuffer = Buffer.from(entropyBytes);
	const newChecksum = checksumBits(entropyBuffer);

	if (newChecksum !== checksum) throw new Error("Invalid mnemonic checksum");

	return entropyBuffer.toString("hex");
}

function entropyToMnemonic(
	entropy: string,
	wordlist: string[] = DEFAULT_WORDLIST,
): string {
	const entropyBuffer = Buffer.from(entropy, "hex");
	const entropyBits = bytesToBinary([].slice.call(entropyBuffer));
	const checksum = checksumBits(entropyBuffer);

	const bits = entropyBits + checksum;
	const chunks = bits.match(/(.{1,11})/g);

	if (!chunks) throw new Error("no chunks");

	const words = chunks.map((binary) => {
		const index = Number.parseInt(binary, 2);
		return wordlist[index];
	});

	return words.join(" ");
}

function generateMnemonic(
	strength: number = DEFAULT_STRENGTH,
	wordlist?: string[],
): string {
	const randomBytesBuffer = Buffer.from(randomBytes(strength / 8));
	return entropyToMnemonic(randomBytesBuffer.toString("hex"), wordlist);
}

function validateMnemonic(mnemonic: string, wordlist?: string[]): boolean {
	try {
		mnemonicToEntropy(mnemonic, wordlist);
	} catch (e) {
		return false;
	}
	return true;
}

function checksumBits(entropyBuffer: Buffer): string {
	const hash = createHash("sha256").update(entropyBuffer).digest();

	// Calculated constants from BIP39
	const ENT = entropyBuffer.length * 8;
	const CS = ENT / 32;

	return bytesToBinary([].slice.call(hash)).slice(0, CS);
}

function salt(password: string): string {
	// Using unorm to get proper unicode string, string.normalize might not work well for some verions of browser
	return `mnemonic ${unorm.nfkd(password) || ""}`;
}

//=========== helper methods from bitcoinjs-lib ========
function bytesToBinary(bytes: number[]): string {
	return bytes.map((x) => lpad(x.toString(2), "0", 8)).join("");
}

function lpad(str: string, padString: string, length: number): string {
	let paddedStr = str;
	while (paddedStr.length < length) paddedStr = padString + paddedStr;
	return paddedStr;
}

function setDefaultWordlist(language: string): void {
	const result = wordlists[language];
	if (!result) {
		throw new Error(`Could not find wordlist for language "${language}"`);
	}
	DEFAULT_WORDLIST = result;
}

function getDefaultWordlist(): string {
	if (!DEFAULT_WORDLIST) {
		throw new Error("No Default Wordlist set");
	}

	const isMatchingWordlist = (language: string): boolean => {
		return wordlists[language].every(
			(word, index) => word === DEFAULT_WORDLIST[index],
		);
	};

	const validLanguages = Object.keys(wordlists).filter(
		(language) =>
			language !== "JA" && language !== "EN" && isMatchingWordlist(language),
	);

	return validLanguages[0] || "";
}

export {
	mnemonicToSeed,
	mnemonicToSeedSync,
	mnemonicToSeedHex,
	mnemonicToEntropy,
	entropyToMnemonic,
	generateMnemonic,
	validateMnemonic,
	setDefaultWordlist,
	getDefaultWordlist,
	wordlists,
};

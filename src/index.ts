import { Buffer } from "@craftzdog/react-native-buffer";
import crypto from "react-native-quick-crypto";
import wordlists from "./wordlists/index";

const { pbkdf2Sync, createHash, randomBytes } = crypto;

let DEFAULT_WORDLIST = wordlists.english;
const DEFAULT_STRENGTH = 128;
const INVALID_MNEMONIC = "Invalid mnemonic";
const INVALID_ENTROPY = "Invalid entropy";
const INVALID_CHECKSUM = "Invalid mnemonic checksum";

function normalize(str: string): string {
	return str.normalize("NFKD");
}

function lpad(str: string, padString: string, length: number): string {
	let paddedStr = str;
	while (paddedStr.length < length) {
		paddedStr = padString + paddedStr;
	}
	return paddedStr;
}

function binaryToByte(bin: string): number {
	return Number.parseInt(bin, 2);
}

function bytesToBinary(bytes: number[]): string {
	return bytes.map((x: number): string => lpad(x.toString(2), "0", 8)).join("");
}

function deriveChecksumBits(entropyBuffer: Buffer): string {
	// Calculated constants from BIP39
	const ENT = entropyBuffer.length * 8;
	const CS = ENT / 32;
	const hash = createHash("sha256").update(entropyBuffer).digest();
	return bytesToBinary(Array.from(hash)).slice(0, CS);
}

function salt(password: string): string {
	return `mnemonic${password}`;
}

function mnemonicToSeed(mnemonic: string, password = ""): Buffer {
	const mnemonicBuffer = Buffer.from(normalize(mnemonic), "utf8");
	const saltBuffer = Buffer.from(salt(normalize(password)), "utf8");
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

function mnemonicToEntropy(
	mnemonic: string,
	wordlist: string[] = DEFAULT_WORDLIST,
): string {
	const words = normalize(mnemonic).split(" ");
	if (words.length % 3 !== 0) {
		throw new Error(INVALID_MNEMONIC);
	}

	// Convert word indices to 11 bit binary strings
	const bits = words
		.map((word) => {
			const index = wordlist.indexOf(word);
			if (index === -1) {
				throw new Error(INVALID_MNEMONIC);
			}
			return lpad(index.toString(2), "0", 11);
		})
		.join("");

	// Split the binary string into ENT/CS
	const dividerIndex = Math.floor(bits.length / 33) * 32;
	const entropyBits = bits.slice(0, dividerIndex);
	const checksumBits = bits.slice(dividerIndex);

	// Calculate the checksum and compare
	const entropyBytes = entropyBits.match(/(.{1,8})/g)?.map(binaryToByte);
	if (!entropyBytes) {
		throw new Error(INVALID_ENTROPY);
	}
	if (entropyBytes.length < 16) {
		throw new Error(INVALID_ENTROPY);
	}
	if (entropyBytes.length > 32) {
		throw new Error(INVALID_ENTROPY);
	}
	if (entropyBytes.length % 4 !== 0) {
		throw new Error(INVALID_ENTROPY);
	}

	const entropy = Buffer.from(entropyBytes);
	const newChecksum = deriveChecksumBits(entropy);
	if (newChecksum !== checksumBits) {
		throw new Error(INVALID_CHECKSUM);
	}

	return entropy.toString("hex");
}

function entropyToMnemonic(
	entropy: Buffer | string,
	wordlist: string[] = DEFAULT_WORDLIST,
): string {
	if (!Buffer.isBuffer(entropy)) {
		entropy = Buffer.from(entropy, "hex");
	}

	// 128 <= ENT <= 256
	if (entropy.length < 16) {
		throw new TypeError(INVALID_ENTROPY);
	}
	if (entropy.length > 32) {
		throw new TypeError(INVALID_ENTROPY);
	}
	if (entropy.length % 4 !== 0) {
		throw new TypeError(INVALID_ENTROPY);
	}

	const entropyBits = bytesToBinary(Array.from(entropy));
	const checksumBits = deriveChecksumBits(entropy);

	const bits = entropyBits + checksumBits;
	const chunks = bits.match(/(.{1,11})/g);

	if (!chunks) {
		throw new Error("no chunks");
	}

	const words = chunks.map((binary) => {
		const index = binaryToByte(binary);
		return wordlist[index];
	});

	return wordlist[0] === "\u3042\u3044\u3053\u304f\u3057\u3093" // Japanese wordlist
		? words.join("\u3000")
		: words.join(" ");
}

function generateMnemonic(
	strength: number = DEFAULT_STRENGTH,
	rng?: (size: number) => Buffer,
	wordlist?: string[],
): string {
	if (strength % 32 !== 0) {
		throw new TypeError(INVALID_ENTROPY);
	}
	rng = rng || ((size: number): Buffer => Buffer.from(randomBytes(size)));
	return entropyToMnemonic(rng(strength / 8), wordlist);
}

function validateMnemonic(mnemonic: string, wordlist?: string[]): boolean {
	try {
		mnemonicToEntropy(mnemonic, wordlist);
	} catch (e) {
		return false;
	}

	return true;
}

function setDefaultWordlist(language: string): void {
	const result = wordlists[language];
	if (result) {
		DEFAULT_WORDLIST = result;
	} else {
		throw new Error(`Could not find wordlist for language "${language}".`);
	}
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
	mnemonicToEntropy,
	entropyToMnemonic,
	generateMnemonic,
	validateMnemonic,
	setDefaultWordlist,
	getDefaultWordlist,
	wordlists,
};

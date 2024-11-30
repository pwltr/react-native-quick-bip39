import unorm from "unorm";
import crypto from "react-native-quick-crypto";
import { Buffer } from "@craftzdog/react-native-buffer";

import CS_WORDLIST from "./wordlists/cs.json";
import EN_WORDLIST from "./wordlists/en.json";
import ES_WORDLIST from "./wordlists/es.json";
import FR_WORDLIST from "./wordlists/fr.json";
import IT_WORDLIST from "./wordlists/it.json";
import JA_WORDLIST from "./wordlists/ja.json";
import KO_WORDLIST from "./wordlists/ko.json";
import PT_WORDLIST from "./wordlists/pt.json";
import ZH_WORDLIST from "./wordlists/zh.json";

const { pbkdf2Sync, createHash, randomBytes } = crypto;

const DEFAULT_STRENGTH = 128;

export const Wordlists = {
  cs: CS_WORDLIST,
  en: EN_WORDLIST,
  es: ES_WORDLIST,
  fr: FR_WORDLIST,
  ja: JA_WORDLIST,
  it: IT_WORDLIST,
  ko: KO_WORDLIST,
  pt: PT_WORDLIST,
  zh: ZH_WORDLIST,
};

export function mnemonicToSeed(
  mnemonic: string,
  password: string = ""
): Buffer {
  const mnemonicBuffer = Buffer.from(mnemonic, "utf8");
  const saltBuffer = Buffer.from(salt(password), "utf8");
  const seedArrayBuffer = pbkdf2Sync(mnemonicBuffer, saltBuffer, 2048, 64, "sha512");
  const seedBuffer = Buffer.from(seedArrayBuffer);
  return seedBuffer;
}

export function mnemonicToSeedHex(
  mnemonic: string,
  password: string = ""
): string {
  return mnemonicToSeed(mnemonic, password).toString("hex");
}

export function mnemonicToEntropy(
  mnemonic: string,
  wordlist: string[] = EN_WORDLIST
): string {
  const words = mnemonic.split(" ");
  if (words.length % 3 !== 0) throw new Error("Invalid mnemonic");

  // convert word indices to 11 bit binary strings
  const bits = words
    .map((word) => {
      const index = wordlist.indexOf(word);
      return lpad(index.toString(2), "0", 11);
    })
    .join("");

  // split the binary string into ENT/CS
  const dividerIndex = Math.floor(bits.length / 33) * 32;
  const entropy = bits.slice(0, dividerIndex);
  const checksum = bits.slice(dividerIndex);

  // calculate the checksum and compare
  const entropyBytes = entropy.match(/(.{1,8})/g)?.map((bin) => parseInt(bin, 2));

  if (!entropyBytes) throw new Error("no entropyBytes");

  const entropyBuffer = Buffer.from(entropyBytes);
  const newChecksum = checksumBits(entropyBuffer);

  if (newChecksum !== checksum) throw new Error("Invalid mnemonic checksum");

  return entropyBuffer.toString("hex");
}

export function entropyToMnemonic(
  entropy: string,
  wordlist: string[] = EN_WORDLIST
): string {
  const entropyBuffer = Buffer.from(entropy, "hex");
  const entropyBits = bytesToBinary([].slice.call(entropyBuffer));
  const checksum = checksumBits(entropyBuffer);

  const bits = entropyBits + checksum;
  const chunks = bits.match(/(.{1,11})/g);

  if (!chunks) throw new Error("no chunks");

  const words = chunks.map((binary) => {
    const index = parseInt(binary, 2);
    return wordlist[index];
  });

  return words.join(" ");
}

export function generateMnemonic(
  strength: number = DEFAULT_STRENGTH,
  wordlist?: string[]
): string {
  const randomBytesBuffer = Buffer.from(randomBytes(strength / 8));
  return entropyToMnemonic(randomBytesBuffer.toString("hex"), wordlist);
}

export function validateMnemonic(mnemonic: string, wordlist?: string[]): boolean {
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
  //Using unorm to get proper unicode string, string.normalize might not work well for some verions of browser
  return "mnemonic" + (unorm.nfkd(password) || "");
}

//=========== helper methods from bitcoinjs-lib ========
function bytesToBinary(bytes: number[]): string {
  return bytes
    .map((x) => lpad(x.toString(2), "0", 8))
    .join("");
}

function lpad(str: string, padString: string, length: number): string {
  while (str.length < length) str = padString + str;
  return str;
}

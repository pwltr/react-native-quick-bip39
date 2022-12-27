# ⚡️ react-native-quick-bip39

A react-native ready very fast implementation of bip39 using [react-native-quick-crypto](https://github.com/margelo/react-native-quick-crypto) and [react-native-quick-base64](https://github.com/craftzdog/react-native-quick-base64)

All methods are sync, as react-native-quick-crypto uses JSI under the hood.

### Reminder for developers

**_Please remember to allow recovery from mnemonic phrases that have invalid checksums (or that you don't have the wordlist)_**

When a checksum is invalid, warn the user that the phrase is not something generated by your app, and ask if they would like to use it anyway. This way, your app only needs to hold the wordlists for your supported languages, but you can recover phrases made by other apps in other languages.

However, there should be other checks in place, such as checking to make sure the user is inputting 12 words or more separated by a space. ie. `phrase.trim().split(/\s+/g).length >= 12`

## Installation

```
yarn add @dreson4/react-native-quick-bip39
```

If you don't yet have react-native-quick-crypto and react-native-quick-base64 installed then run

```
yarn add react-native-quick-crypto
yarn add react-native-quick-base64
cd ios && pod install
```

Or see [react-native-quick-crypto](https://github.com/margelo/react-native-quick-crypto) for further installation instructions if needed.

## Replace `crypto-browserify`

If you are using a library that depends on `crypto`, instead of polyfilling it with `crypto-browserify` (or `react-native-crypto`) you can use `react-native-quick-crypto` for a fully native implementation. This way you can get much faster crypto operations with just a single-line change!

In your `babel.config.js`, add a module resolver to replace `crypto` with `react-native-quick-crypto`:

```diff
module.exports = {
  presets: ['module:metro-react-native-babel-preset'],
  plugins: [
+   [
+     'module-resolver',
+     {
+       alias: {
+         'crypto': 'react-native-quick-crypto',
+         'stream': 'stream-browserify',
+         'buffer': '@craftzdog/react-native-buffer',
+       },
+     },
+   ],
    ...
  ],
};
```

Then restart your bundler using `yarn start --reset-cache`.

Now, all imports for `crypto` will be resolved as `react-native-quick-crypto` instead.

> 💡 Since react-native-quick-crypto depends on `stream` and `buffer`, we can resolve those to `stream-browserify` and @craftzdog's `react-native-buffer` (which is faster than `buffer` because it uses JSI for base64 encoding and decoding).

## Examples

```js
import {
  generateMnemonic,
  mnemonicToSeedHex,
  validateMnemonic,
  entropyToMnemonic,
  mnemonicToEntropy,
  Wordlists,
} from "@dreson4/react-native-quick-bip39";

// Generate a random mnemonic defaults to 128-bits of entropy
generateMnemonic(256);
// => reveal man culture nominee tag abuse keen behave refuse warfare crisp thunder valve knock unique try fold energy torch news thought access hawk table

//For other languages included see Worldlists
generateMnemonic(256, Worldlists.ko); //returns korean mnemonic

mnemonicToSeedHex("basket actual");
// => '5cf2d4a8b0355e90295bdfc565a022a409af063d5365bb57bf74d9528f494bfa4400f53d8349b80fdae44082d7f9541e1dba2b003bcfec9d0d53781ca676651f'

mnemonicToSeed("basket actual");
// => <Buffer 5c f2 d4 a8 b0 35 5e 90 29 5b df c5 65 a0 22 a4 09 af 06 3d 53 65 bb 57 bf 74 d9 52 8f 49 4b fa 44 00 f5 3d 83 49 b8 0f da e4 40 82 d7 f9 54 1e 1d ba 2b ...>

validateMnemonic(myMnemonic);
// => true

validateMnemonic("basket actual");
// => false
```

## Credits

- [react-native-bip39](https://github.com/novalabio/react-native-bip39)
- [Original Javascript implementation of Bitcoin BIP39](https://github.com/bitcoinjs/bip39)

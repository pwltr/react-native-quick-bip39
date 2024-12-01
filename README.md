# ⚡️ react-native-quick-bip39

A fast implementation of `bip39` using [react-native-quick-crypto](https://github.com/margelo/react-native-quick-crypto)

All methods are sync, as `react-native-quick-crypto` uses JSI under the hood.

### Reminder for developers

**_Please remember to allow recovery from mnemonic phrases that have invalid checksums (or that you don't have the wordlist)_**

When a checksum is invalid, warn the user that the phrase is not something generated by your app, and ask if they would like to use it anyway. This way, your app only needs to hold the wordlists for your supported languages, but you can recover phrases made by other apps in other languages.

However, there should be other checks in place, such as checking to make sure the user is inputting 12 words or more separated by a space. ie. `phrase.trim().split(/\s+/g).length >= 12`

## Installation

```
yarn add react-native-quick-bip39
```

## Drop-in replacement for `bip39`

This library exposes all the same methods from the [original JavaScript implementation](https://github.com/bitcoinjs/bip39). If your react-native project depends on that, you can modify your `metro.config.js` to replace all calls with a fully native implementation:

Use the [`resolveRequest`](https://facebook.github.io/metro/docs/resolution#resolverequest-customresolver) configuration option in your `metro.config.js`

```js
config.resolver.resolveRequest = (context, moduleName, platform) => {
  if (moduleName === 'bip39') {
    // when importing bip39, resolve to react-native-quick-bip39
    return context.resolveRequest(
      context,
      'react-native-quick-bip39',
      platform,
    )
  }

  // otherwise chain to the standard Metro resolver.
  return context.resolveRequest(context, moduleName, platform)
}
```

Then restart your bundler using `yarn start --reset-cache`.

> 💡 Since `react-native-quick-crypto` depends on `stream` and `buffer`, we can optionally resolve those to `stream-browserify` and @craftzdog's `react-native-buffer`. See [documentation](https://github.com/margelo/react-native-quick-crypto).

## Examples

```js
import {
  generateMnemonic,
  mnemonicToSeedHex,
  mnemonicToSeed,
  validateMnemonic,
  entropyToMnemonic,
  mnemonicToEntropy,
  wordlists,
} from "react-native-quick-bip39";

// Generate a random mnemonic defaults to 128-bits of entropy
generateMnemonic(256);
// => reveal man culture nominee tag abuse keen behave refuse warfare crisp thunder valve knock unique try fold energy torch news thought access hawk table

// For other languages included see Worldlists
generateMnemonic(256, wordlists.korean); // returns korean mnemonic

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

- [@dreson4/react-native-quick-bip39](https://github.com/dreson4/react-native-quick-bip39)
- [react-native-bip39](https://github.com/novalabio/react-native-bip39)
- [Original Javascript implementation of Bitcoin BIP39](https://github.com/bitcoinjs/bip39)

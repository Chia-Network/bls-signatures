## bls-signatures

JavaScript library that implements BLS signatures with aggregation as in [Boneh, Drijvers, Neven 2018](https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html), using the relic toolkit for cryptographic primitives (pairings, EC, hashing).

This library is a JavaScript port of the [Chia Network's BLS lib](https://github.com/Chia-Network/bls-signatures). We also have typings, so you can use it with TypeScript too!

### Usage

```bash
npm i bls-signatures --save
```
```javascript
const { PrivateKey } = require('bls-js');
const privateKey = PrivateKey.fromSeed(Buffer.from([1,2,3]));
const sig = privateKey.sign(Buffer.from("Hello world!"));
sig.verify();
```

Please refer to the library's [typings](../../js-bindings/blsjs.d.ts) or detailed API information. Use cases can be found in the [original lib's readme](../../README.md).

### Build

Building requires Node.js (with npm) and [Emcripten](https://emscripten.org/docs/getting_started/downloads.html) to be installed.
The build process is the same as for the c++ lib, with one additional step: pass the Emscripten toolchain file as an option to CMake.
From the project root directory, run:
```
git submodule update --init --recursive
mkdir js_build
cd js_build
cmake ../ -DCMAKE_TOOLCHAIN_FILE={path_to_your_emscripten_installation}/emsdk/emscripten/{version}/cmake/Modules/Platform/Emscripten.cmake
cmake --build . --
```

### Run tests

To run tests, build the library, then go to the `js_bindings` folder in the build directory and run
```bash
npm test
```
## BLS.js

This library is a JavaScript port of the BLS lib. We also have typings, so you can use it with TypeScript too!

### Usage

```bash
npm i bls-js
```
```javascript
const { PrivateKey } = require('bls-js');
const privateKey = PrivateKey.fromSeed(Buffer.from([1,2,3]));
const sig = privateKey.sign(Buffer.from("Hello world!"));
sig.verify();
```

You can look at [typings](./blsjs.d.ts) to see how the library's API looks like. Use cases can be found in the [original lib's readme](../README.md).

### Build

Build requires Node.js (with npm) and [Emcripten](https://emscripten.org/docs/getting_started/downloads.html) installed.
The build process is the same as for c++ lib, with one additional step: pass Emscripten toolchain file as an option to CMake.
From the project root directory, run:
```
git submodule update --init --recursive
mkdir js_build
cd js_build
cmake ../ -DCMAKE_TOOLCHAIN_FILE=/home/anton/Programs/emsdk/emscripten/1.38.25/cmake/Modules/Platform/Emscripten.cmake
cmake --build . --
```

### Run tests

To run tests, build the library, go to the `js_bindings` folder in the build directory and run
```bash
npm test
```
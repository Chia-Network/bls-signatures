# BLS Signatures implementation

![Build](https://github.com/Chia-Network/bls-signatures/workflows/Build/badge.svg)
![PyPI](https://img.shields.io/pypi/v/blspy?logo=pypi)
![PyPI - Format](https://img.shields.io/pypi/format/blspy?logo=pypi)
![GitHub](https://img.shields.io/github/license/Chia-Network/bls-signatures?logo=Github)

[![Total alerts](https://img.shields.io/lgtm/alerts/g/Chia-Network/bls-signatures.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/Chia-Network/bls-signatures/alerts/)
[![Language grade: JavaScript](https://img.shields.io/lgtm/grade/javascript/g/Chia-Network/bls-signatures.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/Chia-Network/bls-signatures/context:javascript)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/Chia-Network/bls-signatures.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/Chia-Network/bls-signatures/context:python)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/Chia-Network/bls-signatures.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/Chia-Network/bls-signatures/context:cpp)

NOTE: THIS LIBRARY IS A DRAFT AND NOT YET REVIEWED FOR SECURITY
NOTE: THIS LIBRARY WAS SHIFTED TO THE IETF BLS SPECIFICATION ON 7/16/20 SOME
DOCUMENTATION IS NOT YET UPDATED

Implements BLS signatures with aggregation as in
[Boneh, Drijvers, Neven 2018](https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html)
, using [relic toolkit](https://github.com/relic-toolkit/relic)
for cryptographic primitives (pairings, EC, hashing).
The [BLS12-381](https://github.com/zkcrypto/pairing/tree/master/src/bls12_381)
curve is used. The original spec is
[here](https://github.com/Chia-Network/bls-signatures/tree/master/SPEC.md).
This library now implements
[IETF BLS RFC](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/).

Features:

* Non-interactive signature aggregation on identical or distinct messages
* Aggregate aggregates (trees)
* Efficient verification (only one pairing per distinct message)
* Security against rogue public key attack, using aggregation info, or proof of
possession
* Aggregate public keys and private keys
* M/N threshold keys and signatures using Joint-Feldman scheme
* HD (BIP32) key derivation
* Key and signature serialization
* Batch verification
* Signature division (divide an aggregate by a previously verified signature)
* [JavaScript bindings](https://github.com/Chia-Network/bls-signatures/tree/master/js-bindings)
* [Python bindings](https://github.com/Chia-Network/bls-signatures/tree/master/python-bindings)
* [Pure python bls12-381 and signatures](https://github.com/Chia-Network/bls-signatures/tree/master/python-impl)

## Import the library

```c++
#include "bls.hpp"
```

## Creating keys and signatures

```c++
// Example seed, used to generate private key. Always use
// a secure RNG with sufficient entropy to generate a seed.
uint8_t seed[] = {0, 50, 6, 244, 24, 199, 1, 25, 52, 88, 192,
                  19, 18, 12, 89, 6, 220, 18, 102, 58, 209,
                  82, 12, 62, 89, 110, 182, 9, 44, 20, 254, 22};

bls::PrivateKey sk = bls::PrivateKey::FromSeed(seed, sizeof(seed));
bls::PublicKey pk = sk.GetPublicKey();

uint8_t msg[] = {100, 2, 254, 88, 90, 45, 23};

bls::Signature sig = sk.Sign(msg, sizeof(msg));
```

## Serializing keys and signatures to bytes

```c++
uint8_t skBytes[bls::PrivateKey::PRIVATE_KEY_SIZE];  // 32 byte array
uint8_t pkBytes[bls::PublicKey::PUBLIC_KEY_SIZE];    // 48 byte array
uint8_t sigBytes[bls::Signature::SIGNATURE_SIZE];    // 96 byte array

sk.Serialize(skBytes);   // 32 bytes
pk.Serialize(pkBytes);   // 48 bytes
sig.Serialize(sigBytes); // 96 bytes
```

## Loading keys and signatures from bytes

```c++
// Takes array of 32 bytes
sk = bls::PrivateKey::FromBytes(skBytes);

// Takes array of 48 bytes
pk = bls::PublicKey::FromBytes(pkBytes);

// Takes array of 96 bytes
sig = bls::Signature::FromBytes(sigBytes);
```

## Verifying signatures

```c++
// Add information required for verification, to sig object
sig.SetAggregationInfo(bls::AggregationInfo::FromMsg(pk, msg, sizeof(msg)));

bool ok = sig.Verify();
```

## Aggregate signatures for a single message

```c++
// Generate some more private keys
seed[0] = 1;
bls::PrivateKey sk1 = bls::PrivateKey::FromSeed(seed, sizeof(seed));
seed[0] = 2;
bls::PrivateKey sk2 = bls::PrivateKey::FromSeed(seed, sizeof(seed));

// Generate first sig
bls::PublicKey pk1 = sk1.GetPublicKey();
bls::Signature sig1 = sk1.Sign(msg, sizeof(msg));

// Generate second sig
bls::PublicKey pk2 = sk2.GetPublicKey();
bls::Signature sig2 = sk2.Sign(msg, sizeof(msg));

// Aggregate signatures together
vector<bls::Signature> sigs = {sig1, sig2};
bls::Signature aggSig = bls::Signature::Aggregate(sigs);

// For same message, public keys can be aggregated into one.
// The signature can be verified the same as a single signature,
// using this public key.
vector<bls::PublicKey> pubKeys = {pk1, pk2};
bls::PublicKey aggPubKey = bls::Signature::Aggregate(pubKeys);
```

## Aggregate signatures for different messages

```c++
// Generate one more key and message
seed[0] = 3;
bls::PrivateKey sk3 = bls::PrivateKey::FromSeed(seed, sizeof(seed));
bls::PublicKey pk3 = sk3.GetPublicKey();
uint8_t msg2[] = {100, 2, 254, 88, 90, 45, 23};

// Generate the signatures, assuming we have 3 private keys
sig1 = sk1.Sign(msg, sizeof(msg));
sig2 = sk2.Sign(msg, sizeof(msg));
bls::Signature sig3 = sk3.Sign(msg2, sizeof(msg2));

// They can be noninteractively combined by anyone
// Aggregation below can also be done by the verifier, to
// make batch verification more efficient
vector<bls::Signature> sigsL = {sig1, sig2};
bls::Signature aggSigL = bls::Signature::Aggregate(sigsL);

// Arbitrary trees of aggregates
vector<bls::Signature> sigsFinal = {aggSigL, sig3};
bls::Signature aggSigFinal = bls::Signature::Aggregate(sigsFinal);

// Serialize the final signature
aggSigFinal.Serialize(sigBytes);
```

## Verify aggregate signature for different messages

```c++
// Deserialize aggregate signature
aggSigFinal = bls::Signature::FromBytes(sigBytes);

// Create aggregation information (or deserialize it)
bls::AggregationInfo a1 = bls::AggregationInfo::FromMsg(pk1, msg, sizeof(msg));
bls::AggregationInfo a2 = bls::AggregationInfo::FromMsg(pk2, msg, sizeof(msg));
bls::AggregationInfo a3 = bls::AggregationInfo::FromMsg(pk3, msg2, sizeof(msg2));
vector<bls::AggregationInfo> infos = {a1, a2};
bls::AggregationInfo a1a2 = bls::AggregationInfo::MergeInfos(infos);
vector<bls::AggregationInfo> infos2 = {a1a2, a3};
bls::AggregationInfo aFinal = bls::AggregationInfo::MergeInfos(infos2);

// Verify final signature using the aggregation info
aggSigFinal.SetAggregationInfo(aFinal);
ok = aggSigFinal.Verify();

// If you previously verified a signature, you can also divide
// the aggregate signature by the signature you already verified.
ok = aggSigL.Verify();
vector<bls::Signature> cache = {aggSigL};
aggSigFinal = aggSigFinal.DivideBy(cache);

// Final verification is now more efficient
ok = aggSigFinal.Verify();
```

## Aggregate private keys

```c++
vector<bls::PrivateKey> privateKeysList = {sk1, sk2};
vector<bls::PublicKey> pubKeysList = {pk1, pk2};

// Create an aggregate private key, that can generate
// aggregate signatures
const bls::PrivateKey aggSk = bls::PrivateKey::Aggregate(
        privateKeys, pubKeys);

bls::Signature aggSig3 = aggSk.Sign(msg, sizeof(msg));
```

## HD keys

```c++
// Random seed, used to generate master extended private key
uint8_t seed[] = {1, 50, 6, 244, 24, 199, 1, 25, 52, 88, 192,
                  19, 18, 12, 89, 6, 220, 18, 102, 58, 209,
                  82, 12, 62, 89, 110, 182, 9, 44, 20, 254, 22};

bls::ExtendedPrivateKey esk = bls::ExtendedPrivateKey::FromSeed(
        seed, sizeof(seed));

bls::ExtendedPublicKey epk = esk.GetExtendedPublicKey();

// Use i >= 2^31 for hardened keys
bls::ExtendedPrivateKey skChild = esk.PrivateChild(0)
                                .PrivateChild(5);

bls::ExtendedPublicKey pkChild = epk.PublicChild(0)
                               .PublicChild(5);

// Serialize extended keys
uint8_t buffer1[bls::ExtendedPublicKey::EXTENDED_PUBLIC_KEY_SIZE];   // 93 bytes
uint8_t buffer2[bls::ExtendedPrivateKey::EXTENDED_PRIVATE_KEY_SIZE]; // 77 bytes

pkChild.Serialize(buffer1);
skChild.Serialize(buffer2);
```

## Prepend PK method

```c++
// Can use proofs of possession to avoid keeping track of metadata
PrependSignature prepend1 = sk1.SignPrepend(msg, sizeof(msg));
PrependSignature prepend2 = sk2.SignPrepend(msg, sizeof(msg));

std::vector<PublicKey> prependPubKeys = {pk1, pk2};
uint8_t messageHash[BLS::MESSAGE_HASH_LEN];
Util::Hash256(messageHash, msg, sizeof(msg));
std::vector<const uint8_t*> hashes = {messageHash, messageHash};

std::vector<PrependSignature> prependSigs = {prepend1, prepend2};
PrependSignature prependAgg = PrependSignature::Aggregate(prependSigs);

prependAgg.Verify(hashes, prependPubKeys);
```

## Build

Cmake 3.14+, a c++ compiler, and python3 (for bindings) are required for building.

```bash
git submodule update --init --recursive

mkdir build
cd build
cmake ../
cmake --build . -- -j 6
```

### Run tests

```bash
./build/src/runtest
```

### Run benchmarks

```bash
./build/src/runbench
```

### Link the library to use it

```bash
g++ -Wl,-no_pie  -Ibls-signatures/contrib/relic/include -Ibls-signatures/build/contrib/relic/incl
ude -Ibls-signatures/src/  -L./bls-signatures/build/ -l bls  yourfile.cpp
```

## Notes on dependencies

Changes performed to relic: Added config files for Chia, and added gmp include
in relic.h, new ep_map and ep2_map, new ep_pck and ep2_pck. Custom inversion
function. Note: relic is used with the Apache 2.0 license.

Libsodium and GMP are optional dependencies: libsodium gives secure memory
allocation, and GMP speeds up the library by ~ 3x. To install them, either
download them from github and follow the instructions for each repo, or use
a package manager like APT or brew. You can follow the recipe used to build
python wheels for multiple platforms in `.github/workflows/`

## Discussion

Discussion about this library and other Chia related development is in the #dev
channle of Chia's [public Keybase channels](https://keybase.io/team/chia_network.public).

## Code style

* Always use uint8_t for bytes
* Use size_t for size variables
* Uppercase method names
* Prefer static constructors
* Avoid using templates
* Objects allocate and free their own memory
* Use cpplint with default rules

There are three types of signatures: InsecureSignatures (simple signatures
which are not secure by themselves, due to rogue public keys), Signatures
(secure signatures that require AggregationInfo to aggregate), and
PrependSignatures, which prepend public keys to messages, making them secure.

## ci Building

The primary build process for this repository is to use GitHub Actions to
build binary wheels for MacOS, Linux (x64 and aarch64), and Windows and publish
them with a source wheel on PyPi. See `.github/workflows/build.yml`. CMake uses
[FetchContent](https://cmake.org/cmake/help/latest/module/FetchContent.html)
to download [pybind11](https://github.com/pybind/pybind11) for the Python
bindings and relic from a chia relic forked reporitory. Building is then
managed by [cibuildwheel](https://github.com/joerick/cibuildwheel).
Further installation is then available via `pip install blspy` e.g. The ci
builds include GMP and libsoduium.

## Contributing and workflow

Contributions are welcome and more details are available in chia-blockchain's
[CONTRIBUTING.md](https://github.com/Chia-Network/chia-blockchain/blob/master/CONTRIBUTING.md).

The master branch is usually the currently released latest version on PyPI.
Note that at times bls-signatures/blspy will be ahead of the release version
that chia-blockchain requires in it's master/release version in preparation
for a new chia-blockchain release. Please branch or fork master and then create
a pull request to the master branch. Linear merging is enforced on master and
merging requires a completed review. PRs will kick off a GitHub actions ci build
and analysis of bls-signatures at
[lgtm.com](https://lgtm.com/projects/g/Chia-Network/bls-signatures/?mode=list).
Please make sure your build is passing and that it does not increase alerts
at lgtm.

## Specification and test vectors

The specification and test vectors can be found
[here](https://github.com/Chia-Network/bls-signatures/tree/master/SPEC.md).
Test vectors can also be seen in the python or cpp test files.

## Libsodium license

The libsodium static library is licensed under the ISC license which requires
the following copyright notice.

>ISC License
>
>Copyright (c) 2013-2020
>Frank Denis \<j at pureftpd dot org\>
>
>Permission to use, copy, modify, and/or distribute this software for any
>purpose with or without fee is hereby granted, provided that the above
>copyright notice and this permission notice appear in all copies.
>
>THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
>WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
>MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
>ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
>WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
>ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
>OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

## GMP license

GMP is distributed under the [GNU LGPL v3 license](https://www.gnu.org/licenses/lgpl-3.0.html)

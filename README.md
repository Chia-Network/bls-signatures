### BLS Signatures implementation

NOTE: THIS LIBRARY IS A DRAFT AND NOT YET REVIEWED FOR SECURITY

Implements BLS signatures with aggregation as in [Boneh, Drijvers, Neven 2018](https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html), using
[relic toolkit](https://github.com/relic-toolkit/relic) for cryptographic primitives (pairings, EC, hashing).
The BLS12-381 curve is used.

Features:
* Non-interactive signature aggregation on identical or distinct messages
* Aggregate aggregates (trees)
* Efficient verification (only one pairing per distinct message)
* Security against rogue public key attack
* Aggregate public keys and private keys
* HD (BIP32) key derivation
* Key and signature serialization
* Batch verification
* Signature division (divide an aggregate by a previously verified signature)

#### Import the library
```c++
#include "bls.hpp"
```

#### Creating keys and signatures
```c++
// Example seed, used to generate private key. Always use
// a secure RNG with sufficient entropy to generate a seed.
uint8_t seed[] = {0, 50, 6, 244, 24, 199, 1, 25, 52, 88, 192,
                  19, 18, 12, 89, 6, 220, 18, 102, 58, 209,
                  82, 12, 62, 89, 110, 182, 9, 44, 20, 254, 22};

BLSPrivateKey sk = BLSPrivateKey::FromSeed(seed, sizeof(seed));
BLSPublicKey pk = sk.GetPublicKey();

uint8_t msg[] = {100, 2, 254, 88, 90, 45, 23};

BLSSignature sig = sk.Sign(msg, sizeof(msg));
```

#### Serializing keys and signatures to bytes
```c++
uint8_t skBytes[BLSPrivateKey::PRIVATE_KEY_SIZE];  // 32 byte array
uint8_t pkBytes[BLSPublicKey::PUBLIC_KEY_SIZE];    // 48 byte array
uint8_t sigBytes[BLSSignature::SIGNATURE_SIZE];    // 96 byte array

sk.Serialize(skBytes);   // 32 bytes
pk.Serialize(pkBytes);   // 48 bytes
sig.Serialize(sigBytes); // 96 bytes
```

#### Loading keys and signatures from bytes
```c++
// Takes array of 32 bytes
sk = BLSPrivateKey::FromBytes(skBytes);

// Takes array of 48 bytes
pk = BLSPublicKey::FromBytes(pkBytes);

// Takes array of 96 bytes
sig = BLSSignature::FromBytes(sigBytes);
```

#### Verifying signatures
```c++
// Add information required for verification, to sig object
sig.SetAggregationInfo(AggregationInfo::FromMsg(pk, msg, sizeof(msg)));

bool ok = BLS::Verify(sig);
```

#### Aggregate signatures for a single message
```c++
// Generate some more private keys
seed[0] = 1;
BLSPrivateKey sk1 = BLSPrivateKey::FromSeed(seed, sizeof(seed));
seed[0] = 2;
BLSPrivateKey sk2 = BLSPrivateKey::FromSeed(seed, sizeof(seed));

// Generate first sig
BLSPublicKey pk1 = sk1.GetPublicKey();
BLSSignature sig1 = sk1.Sign(msg, sizeof(msg));

// Generate second sig
BLSPublicKey pk2 = sk2.GetPublicKey();
BLSSignature sig2 = sk2.Sign(msg, sizeof(msg));

// Aggregate signatures together
vector<const BLSSignature> sigs = {sig1, sig2};
BLSSignature aggSig = BLS::AggregateSigs(sigs);

// For same message, public keys can be aggregated into one.
// The signature can be verified the same as a single signature,
// using this public key.
vector<const BLSPublicKey> pubKeys = {pk1, pk2};
BLSPublicKey aggPubKey = BLS::AggregatePubKeys(pubKeys, true);
```

#### Aggregate signatures for different messages
```c++
// Generate one more key
seed[0] = 3;
BLSPrivateKey sk3 = BLSPrivateKey::FromSeed(seed, sizeof(seed));

// Generate the signatures, assuming we have 3 private keys
BLSSignature sig1 = sk1.Sign(msg, sizeof(msg));
BLSSignature sig2 = sk2.Sign(msg, sizeof(msg));
BLSSignature sig3 = sk3.Sign(msg2, sizeof(msg2));

// They can be noninteractively combined by anyone
// Aggregation below can also be done by the verifier, to
// make batch verification more efficient
vector<const BLSSignature> sigsL = {sig1, sig2};
BLSSignature aggSigL = BLS::AggregateSigs(sigsL);

// Arbitrary trees of aggregates
vector<BLSSignature> sigsFinal = {aggSigL, sig3};
BLSSignature aggSigFinal = BLS::AggregateSigs(sigsFinal);

// Serialize the final signature
aggSigFinal.Serialize(sigBytes);
```

#### Verify aggregate signature for different messages
```c++
// Deserialize aggregate signature
aggSigFinal = BLSSignature::FromBytes(sigBytes);

// Create aggregation information (or deserialize it)
AggregationInfo a1 = AggregationInfo::FromMsg(pk1, msg, sizeof(msg));
AggregationInfo a2 = AggregationInfo::FromMsg(pk2, msg, sizeof(msg));
AggregationInfo a3 = AggregationInfo::FromMsg(pk3, msg2, sizeof(msg2));
vector<AggregationInfo> infos = {a1, a2};
AggregationInfo a1a2 = AggregationInfo::Merge(infos);
vector<AggregationInfo> infos2 = {a1a2, a3};
AggregationInfo aFinal = AggregationInfo::Merge(infos2);

// Verify final signature using the aggregation info
aggSigFinal.SetAggregationInfo(aFinal);
ok = BLS::Verify(aggSigFinal);

// If you previously verified a signature, you can also divide
// the aggregate signature by the signature you already verified.
ok = BLS::Verify(aggSigL);
vector<const BLSSignature> cache = {aggSigL};
aggSigFinal = aggSig2.DivideBy(cache);

// Final verification is now more efficient
ok = BLS::Verify(aggSigFinal));
```

#### Aggregate private keys
```c++
vector<const BLSPrivateKey> privateKeys = {sk1, sk2};
vector<const BLSPublicKey> pubKeys = {pk1, pk2};

// Create an aggregate private key, that can generate
// aggregate signatures
const BLSPrivateKey aggSk = BLS::AggregatePrivKeys(
        privateKeys, pubKeys, true);

BLSSignature aggSig3 = aggSk.Sign(msg, sizeof(msg));
```

#### HD keys
```c++
// Random seed, used to generate master extended private key
uint8_t seed[] = {1, 50, 6, 244, 24, 199, 1, 25, 52, 88, 192,
                  19, 18, 12, 89, 6, 220, 18, 102, 58, 209,
                  82, 12, 62, 89, 110, 182, 9, 44, 20, 254, 22};

ExtendedPrivateKey esk = ExtendedPrivateKey::FromSeed(
        seed, sizeof(seed));

ExtendedPublicKey epk = esk.GetExtendedPublicKey();

// Use i >= 2^31 for hardened keys
ExtendedPrivateKey pkChild = esk.PrivateChild(0)
                                .PrivateChild(5);

ExtendedPublicKey skChild = epk.PublicChild(0)
                               .PublicChild(5);

// Serialize extended keys
uint8_t buffer1[ExtendedPublicKey::ExtendedPublicKeySize]   // 93 bytes
uint8_t buffer2[ExtendedPrivateKey::ExtendedPrivateKeySize] // 77 bytes

pkChild.Serialize(buffer1);
skChild.Serialize(buffer2);
```


### Build Dependencies
#### GMP (optional, LGPL v3)
GMP can be used to speed up bignum operations.
```bash
cd lib
gunzip -c gmp-6.1.2.tar.gz | tar xopf -
cd gmp-6.1.2
make clean
./configure
make && make check
make install
```

#### Relic (LGPL v2.1)
If using GMP, replace easy with gmp.
Changes performed: Added config files for Chia, and added gmp include in relic.h.
Allow passing in hash to ep2_map.

```bash
cd lib
gunzip -c catch.tar.gz | tar xopf -
gunzip -c relic.tar.gz | tar xopf -
cd relic
rm CMakeCache.txt
rm -rf relic-target
mkdir -p relic-target
cd relic-target
../preset/chia-easy-linux.sh ../    (or chia-easy-mac if running on a mac)
make -j 6
```

#### Libsodium
Libsodium is used for allocating memory for private keys.
```bash
cd lib
gunzip -c libsodium-1.0.16.tar.gz | tar xopf -
cd libsodium-1.0.16
./configure
make && make check
make install
```

### Make Project
```bash
make
```

### Run tests
```bash
make test
```

### Run benchmarks
```bash
make bench
```

### Link the library to use it
```bash
g++ -Ibls-signatures/lib/relic/include -Ibls-signatures/lib/relic/relic-target/include -Ibls-signatures/src  -L./bls-signatures -l bls yourfilename.cpp
```

### Code style
* Always use uint8_t for bytes
* Use size_t for size variables
* Uppercase method names
* Prefer static constructors
* Avoid using templates
* Objects allocate and free their own memory
* Use cpplint with default rules

### TODO
* Serialize aggregation info
* Optimize performance
* Secure allocation during signing, key derivation
* Threshold signatures
* Full python implementation
* Python bindings
* Remove unnecessary dependency files
* Constant time and side channel attacks
* Adaptor signatures / Blind signatures

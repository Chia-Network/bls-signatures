// Copyright 2018 Chia Network Inc

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef SRC_BLSPRIVATEKEY_HPP_
#define SRC_BLSPRIVATEKEY_HPP_

#include "relic_conf.h"

#if defined GMP && ARITH == GMP
#include <gmp.h>
#endif

#include "blspublickey.hpp"
#include "blssignature.hpp"

class BLSPrivateKey {
 public:
    // Private keys are represented as 32 byte field elements. Note that
    // not all 32 byte integers are valid keys, the private key must be
    // less than the group order (which is in bls.hpp).
    static const size_t PRIVATE_KEY_SIZE = 32;

    // Generates a private key from a seed, similar to HD key generation
    // (hashes the seed), and reduces it mod the group order.
    static BLSPrivateKey FromSeed(
            const uint8_t* seed, size_t seedLen);

    // Construct a private key from a bytearray.
    static BLSPrivateKey FromBytes(const uint8_t* bytes, bool modOrder = false);

    // Construct a private key from another private key. Allocates memory in
    // secure heap, and copies keydata.
    BLSPrivateKey(const BLSPrivateKey& k);
    BLSPrivateKey(BLSPrivateKey&& k);

    ~BLSPrivateKey();

    BLSPublicKey GetPublicKey() const;

    // Insecurely aggregate multiple private keys into one
    static BLSPrivateKey AggregateInsecure(std::vector<BLSPrivateKey> const& privateKeys);

    // Securely aggregate multiple private keys into one by exponentiating the keys with the pubKey hashes first
    static BLSPrivateKey Aggregate(std::vector<BLSPrivateKey> const& privateKeys,
                                   std::vector<BLSPublicKey> const& pubKeys);

    // Compare to different private key
    friend bool operator==(const BLSPrivateKey& a, const BLSPrivateKey& b);
    friend bool operator!=(const BLSPrivateKey& a, const BLSPrivateKey& b);
    BLSPrivateKey& operator=(const BLSPrivateKey& rhs);

    // Serialize the key into bytes
    void Serialize(uint8_t* buffer) const;
    std::vector<uint8_t> Serialize() const;

    // Sign a message
    // The secure variants will also set and return appropriate aggregation info
    BLSInsecureSignature SignInsecure(const uint8_t *msg, size_t len) const;
    BLSInsecureSignature SignInsecurePrehashed(const uint8_t *hash) const;
    BLSSignature Sign(const uint8_t *msg, size_t len) const;
    BLSSignature SignPrehashed(const uint8_t *hash) const;

 private:
    // Don't allow public construction, force static methods
    BLSPrivateKey() {}

    // Multiply private key with n
    BLSPrivateKey Mul(const relic::bn_t n) const;

    // Allocate memory for private key
    void AllocateKeyData();

 private:
    // The actual byte data
    relic::bn_t *keydata{nullptr};
};

#endif  // SRC_BLSPRIVATEKEY_HPP_

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
    static BLSPrivateKey FromBytes(const uint8_t* bytes);

    // Construct a private key from another private key. Allocates memory in
    // secure heap, and copies keydata.
    BLSPrivateKey(const BLSPrivateKey& k);

    ~BLSPrivateKey();

    BLSPublicKey GetPublicKey() const;

    // Compare to different private key
    friend bool operator==(const BLSPrivateKey& a, const BLSPrivateKey& b);
    friend bool operator!=(const BLSPrivateKey& a, const BLSPrivateKey& b);
    BLSPrivateKey& operator=(const BLSPrivateKey& rhs);

    // Simple read-only vector-like interface.
    size_t size() const;
    uint8_t* begin() const;
    uint8_t* end() const;

    relic::bn_t* GetValue() const { return keydata; }

    // Serialize the key into bytes
    void Serialize(uint8_t* buffer) const;

    // Sign a message
    BLSSignature Sign(uint8_t *msg, size_t len) const;
    BLSSignature SignPrehashed(uint8_t *hash) const;

 private:
    // Don't allow public construction, force static methods
    BLSPrivateKey() {}

    // The actual byte data
    relic::bn_t *keydata;

    // Allocate memory for private key
    void AllocateKeyData();
};

#endif  // SRC_BLSPRIVATEKEY_HPP_

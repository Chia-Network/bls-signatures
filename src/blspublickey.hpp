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

#ifndef SRC_BLSPUBLICKEY_HPP_
#define SRC_BLSPUBLICKEY_HPP_

#include <iostream>
#include <vector>

#include "blsutil.hpp"

/** An encapsulated public key. */
class BLSPublicKey {
 public:
    static const size_t PUBLIC_KEY_SIZE = 48;

    // Construct a public key from a byte vector.
    static BLSPublicKey FromBytes(const uint8_t* key);

    // Construct a public key from a native g1 element.
    static BLSPublicKey FromG1(const relic::g1_t* key);

    // Construct a public key from another public key.
    BLSPublicKey(const BLSPublicKey &pubKey);

    // Simple read-only vector-like interface to the pubkey data.
    size_t size() const;
    const uint8_t* begin() const;
    const uint8_t* end() const;
    const uint8_t& operator[](size_t pos) const;

    // Comparator implementation.
    friend bool operator==(BLSPublicKey const &a,  BLSPublicKey const &b);
    friend bool operator!=(BLSPublicKey const &a,  BLSPublicKey const &b);
    friend bool operator<(BLSPublicKey const &a,  BLSPublicKey const &b);
    friend std::ostream &operator<<(std::ostream &os, BLSPublicKey const &s);

    void Serialize(uint8_t *buffer) const;
    void GetPoint(relic::g1_t &output) const { *output = *q; }

    // Returns the first 4 bytes of the serialized pk
    uint32_t GetFingerprint() const;

 private:
    // Don't allow public construction, force static methods
    BLSPublicKey() {}

    static void CompressPoint(uint8_t* result, const relic::g1_t* point);

    // Public key group element
    relic::g1_t q;
    uint8_t data[BLSPublicKey::PUBLIC_KEY_SIZE];
};

#endif  // SRC_BLSPUBLICKEY_HPP_

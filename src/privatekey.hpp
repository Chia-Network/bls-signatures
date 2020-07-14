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

// #include "publickey.hpp"
// #include "signature.hpp"
#include "elements.hpp"

namespace bls {
class PrivateKey {
    friend class BLS;
    // friend class Threshold;
    friend class G1Element;
    friend class G2Element;

public:
    // Private keys are represented as 32 byte field elements. Note that
    // not all 32 byte integers are valid keys, the private key must be
    // less than the group order (which is in bls.hpp).
    static const size_t PRIVATE_KEY_SIZE = 32;

    // Generates a private key from a seed, similar to HD key generation
    // (hashes the seed), and reduces it mod the group order.
    static PrivateKey FromSeed(const uint8_t *seed, size_t seedLen);

    // Construct a private key from a bytearray.
    static PrivateKey FromBytes(const uint8_t *bytes, bool modOrder = false);

    // Construct a private key from a native bn element.
    static PrivateKey FromBN(bn_t sk);

    static PrivateKey Aggregate(std::vector<PrivateKey> const &privateKeys);

    // Construct a private key from another private key. Allocates memory in
    // secure heap, and copies keydata.
    PrivateKey(const PrivateKey &k);
    PrivateKey(PrivateKey &&k);

    ~PrivateKey();

    // PublicKey GetPublicKey() const;
    G1Element GetG1Element() const;
    G2Element GetG2Element() const;

    G2Element GetG2Power(g2_t base) const;

    bool IsZero();

    /*
    // Insecurely aggregate multiple private keys into one
    static PrivateKey AggregateInsecure(std::vector<PrivateKey> const&
    privateKeys);

    // Securely aggregate multiple private keys into one by exponentiating the
    keys with the pubKey hashes first static PrivateKey
    Aggregate(std::vector<PrivateKey> const& privateKeys, std::vector<PublicKey>
    const& pubKeys);
    */

    // Compare to different private key
    friend bool operator==(const PrivateKey &a, const PrivateKey &b);
    friend bool operator!=(const PrivateKey &a, const PrivateKey &b);
    PrivateKey &operator=(const PrivateKey &rhs);

    // Multiply private key by G1 or G2 elements
    friend G1Element &operator*=(G1Element &a, PrivateKey &k);
    friend G1Element &operator*=(PrivateKey &k, G1Element &a);
    friend G1Element operator*(G1Element &a, PrivateKey &k);
    friend G1Element operator*(PrivateKey &k, G1Element &a);

    friend G2Element &operator*=(G2Element &a, PrivateKey &k);
    friend G2Element &operator*=(PrivateKey &k, G2Element &a);
    friend G2Element operator*(G2Element &a, PrivateKey &k);
    friend G2Element operator*(PrivateKey &k, G2Element &a);

    // Serialize the key into bytes
    void Serialize(uint8_t *buffer) const;
    std::vector<uint8_t> Serialize() const;

    G2Element SignG2(
        const uint8_t *msg,
        size_t len,
        const uint8_t *dst,
        size_t dst_len) const;

    G2Element SignG2Prehashed(
        const uint8_t *messageHash,
        const uint8_t *dst,
        size_t dst_len) const;

    /*
    // Sign a message without setting aggreagation info.
    InsecureSignature SignInsecure(const uint8_t *msg, size_t len) const;
    InsecureSignature SignInsecurePrehashed(const uint8_t *hash) const;

    // The secure Signing variants, which also set and return appropriate
    aggregation info. Signature Sign(const uint8_t *msg, size_t len) const;
    Signature SignPrehashed(const uint8_t *hash) const;

    // Helper methods to prepend the public key to the message, allowing secure
    // aggregation by proof of posession of public key. These must be verified
    using
    // VerifyPrepend. These signatures are identical to Insecure signatures, but
    are generated
    // and verified by prepending the pulic keys: Sign(H(pk + H(m))).
    PrependSignature SignPrepend(const uint8_t *msg, size_t len) const;
    PrependSignature SignPrependPrehashed(const uint8_t *msg) const;
    */

private:
    // Don't allow public construction, force static methods
    PrivateKey() {}

    // Multiply private key with n
    PrivateKey Mul(const bn_t n) const;

    // Allocate memory for private key
    void AllocateKeyData();

private:
    // The actual byte data
    bn_t *keydata{nullptr};
};
}  // end namespace bls

#endif  // SRC_BLSPRIVATEKEY_HPP_

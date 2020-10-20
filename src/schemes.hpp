// Copyright 2020 Chia Network Inc

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in coiance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or iied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef SRC_BLSSCHEMES_HPP_
#define SRC_BLSSCHEMES_HPP_

#include <iostream>
#include <vector>

#include "relic_conf.h"

#if defined GMP && ARITH == GMP
#include <gmp.h>
#endif

#include "elements.hpp"
#include "privatekey.hpp"
#include "util.hpp"

using std::vector;

// These are all MPL schemes
namespace bls {

class CoreMPL {
    friend class BasicSchemeMPL;
    friend class AugSchemeMPL;
    friend class PopSchemeMPL;

public:
    // Generates a private key from a seed, similar to HD key generation
    // (hashes the seed), and reduces it mod the group order
    static PrivateKey KeyGen(const vector<uint8_t> seed);

    // Generates a public key from a secret key
    static vector<uint8_t> SkToPk(const PrivateKey &seckey);

    static G1Element SkToG1(const PrivateKey &seckey);

    static G2Element Sign(
        const PrivateKey &seckey,
        const vector<uint8_t> &message,
        const uint8_t *dst,
        int dst_len);

    static bool Verify(
        const vector<uint8_t> &pubkey,
        const vector<uint8_t> &message,
        const vector<uint8_t> &signature,
        const uint8_t *dst,
        int dst_len);

    static bool Verify(
        const G1Element &pubkey,
        const vector<uint8_t> &message,
        const G2Element &signature,
        const uint8_t *dst,
        int dst_len);

    static vector<uint8_t> Aggregate(const vector<vector<uint8_t>> &signatures);

    static G2Element Aggregate(const vector<G2Element> &signatures);

    static G1Element Aggregate(const vector<G1Element> &publicKeys);

    static bool AggregateVerify(
        const vector<vector<uint8_t>> &pubkeys,
        const vector<vector<uint8_t>> &messages,
        const vector<uint8_t> &signature,
        const uint8_t *dst,
        int dst_len);

    static bool AggregateVerify(
        const vector<G1Element> &pubkeys,
        const vector<vector<uint8_t>> &messages,
        const G2Element &signature,
        const uint8_t *dst,
        int dst_len);
    static PrivateKey DeriveChildSk(const PrivateKey& sk, uint32_t index);
    static PrivateKey DeriveChildSkUnhardened(const PrivateKey& sk, uint32_t index);
    static G1Element DeriveChildPkUnhardened(const G1Element& sk, uint32_t index);

private:
    static bool NativeVerify(g1_t *pubKeys, g2_t *mappedHashes, size_t length);
};

class BasicSchemeMPL {
    friend class CoreMPL;

public:
    static const uint8_t *CIPHERSUITE_ID;
    static const int CIPHERSUITE_ID_LEN;
    static PrivateKey KeyGen(const vector<uint8_t> seed) {
        return CoreMPL::KeyGen(seed);
    }

    static vector<uint8_t> SkToPk(const PrivateKey &seckey)
    {
        return CoreMPL::SkToPk(seckey);
    }

    static G1Element SkToG1(const PrivateKey &seckey)
    {
        return CoreMPL::SkToG1(seckey);
    }

    static vector<uint8_t> Aggregate(const vector<vector<uint8_t>> &signatures)
    {
        return CoreMPL::Aggregate(signatures);
    }

    static G2Element Aggregate(const vector<G2Element> &signatures)
    {
        return CoreMPL::Aggregate(signatures);
    }

    static G1Element Aggregate(const vector<G1Element> &publicKeys)
    {
        return CoreMPL::Aggregate(publicKeys);
    }

    static G2Element Sign(
        const PrivateKey &seckey,
        const vector<uint8_t> &message);

    static bool Verify(
        const vector<uint8_t> &pubkey,
        const vector<uint8_t> &message,
        const vector<uint8_t> &signature);

    static bool Verify(
        const G1Element &pubkey,
        const vector<uint8_t> &message,
        const G2Element &signature);

    static bool AggregateVerify(
        const vector<vector<uint8_t>> &pubkeys,
        const vector<vector<uint8_t>> &messages,
        const vector<uint8_t> &signature);

    static bool AggregateVerify(
        const vector<G1Element> &pubkeys,
        const vector<vector<uint8_t>> &messages,
        const G2Element &signature);

    static PrivateKey DeriveChildSk(const PrivateKey& sk, uint32_t index) {
        return CoreMPL::DeriveChildSk(sk, index);
    }
    static PrivateKey DeriveChildSkUnhardened(const PrivateKey& sk, uint32_t index) {
        return CoreMPL::DeriveChildSkUnhardened(sk, index);
    }
    static G1Element DeriveChildPkUnhardened(const G1Element& pk, uint32_t index) {
        return CoreMPL::DeriveChildPkUnhardened(pk, index);
    }
};

class AugSchemeMPL {
    friend class CoreMPL;

public:
    static const uint8_t *CIPHERSUITE_ID;
    static const int CIPHERSUITE_ID_LEN;

    static PrivateKey KeyGen(const vector<uint8_t> seed) {
        return CoreMPL::KeyGen(seed);
    }

    static vector<uint8_t> SkToPk(const PrivateKey &seckey)
    {
        return CoreMPL::SkToPk(seckey);
    }

    static G1Element SkToG1(const PrivateKey &seckey)
    {
        return CoreMPL::SkToG1(seckey);
    }

    static vector<uint8_t> Aggregate(const vector<vector<uint8_t>> &signatures)
    {
        return CoreMPL::Aggregate(signatures);
    }

    static G2Element Aggregate(const vector<G2Element> &signatures)
    {
        return CoreMPL::Aggregate(signatures);
    }

    static G1Element Aggregate(const vector<G1Element> &publicKeys)
    {
        return CoreMPL::Aggregate(publicKeys);
    }

    static G2Element Sign(
        const PrivateKey &seckey,
        const vector<uint8_t> &message);

    // Custom prepended pk
    static G2Element Sign(
        const PrivateKey &seckey,
        const vector<uint8_t> &message,
        const G1Element &prepend_pk);

    static bool Verify(
        const vector<uint8_t> &pubkey,
        const vector<uint8_t> &message,
        const vector<uint8_t> &signature);

    static bool Verify(
        const G1Element &pubkey,
        const vector<uint8_t> &message,
        const G2Element &signature);

    static bool AggregateVerify(
        const vector<vector<uint8_t>> &pubkeys,
        const vector<vector<uint8_t>> &messages,
        const vector<uint8_t> &signature);

    static bool AggregateVerify(
        const vector<G1Element> &pubkeys,
        const vector<vector<uint8_t>> &messages,
        const G2Element &signature);

    static PrivateKey DeriveChildSk(const PrivateKey& sk, uint32_t index) {
        return CoreMPL::DeriveChildSk(sk, index);
    }
    static PrivateKey DeriveChildSkUnhardened(const PrivateKey& sk, uint32_t index) {
        return CoreMPL::DeriveChildSkUnhardened(sk, index);
    }
    static G1Element DeriveChildPkUnhardened(const G1Element& pk, uint32_t index) {
        return CoreMPL::DeriveChildPkUnhardened(pk, index);
    }
};

class PopSchemeMPL {
    friend class CoreMPL;

public:
    static const uint8_t *CIPHERSUITE_ID;
    static const int CIPHERSUITE_ID_LEN;
    static const uint8_t *POP_CIPHERSUITE_ID;
    static const int POP_CIPHERSUITE_ID_LEN;

    static PrivateKey KeyGen(const vector<uint8_t> seed) {
        return CoreMPL::KeyGen(seed);
    }

    static vector<uint8_t> SkToPk(const PrivateKey &seckey)
    {
        return CoreMPL::SkToPk(seckey);
    }

    static G1Element SkToG1(const PrivateKey &seckey)
    {
        return CoreMPL::SkToG1(seckey);
    }

    static vector<uint8_t> Aggregate(const vector<vector<uint8_t>> &signatures)
    {
        return CoreMPL::Aggregate(signatures);
    }

    static G2Element Aggregate(const vector<G2Element> &signatures)
    {
        return CoreMPL::Aggregate(signatures);
    }

    static G1Element Aggregate(const vector<G1Element> &publicKeys)
    {
        return CoreMPL::Aggregate(publicKeys);
    }

    static G2Element Sign(
        const PrivateKey &seckey,
        const vector<uint8_t> &message);

    static bool Verify(
        const vector<uint8_t> &pubkey,
        const vector<uint8_t> &message,
        const vector<uint8_t> &signature);

    static bool Verify(
        const G1Element &pubkey,
        const vector<uint8_t> &message,
        const G2Element &signature);

    static bool AggregateVerify(
        const vector<vector<uint8_t>> &pubkeys,
        const vector<vector<uint8_t>> &messages,
        const vector<uint8_t> &signature);

    static bool AggregateVerify(
        const vector<G1Element> &pubkeys,
        const vector<vector<uint8_t>> &messages,
        const G2Element &signature);

    static G2Element PopProve(const PrivateKey &seckey);

    static bool PopVerify(
        const G1Element &pubkey,
        const G2Element &signature_proof);

    static bool PopVerify(
        const vector<uint8_t> &pubkey,
        const vector<uint8_t> &proof);

    static bool FastAggregateVerify(
        const vector<G1Element> &pubkeys,
        const vector<uint8_t> &message,
        const G2Element &signature);

    static bool FastAggregateVerify(
        const vector<vector<uint8_t>> &pubkeys,
        const vector<uint8_t> &message,
        const vector<uint8_t> &signature);

    static PrivateKey DeriveChildSk(const PrivateKey& sk, uint32_t index) {
        return CoreMPL::DeriveChildSk(sk, index);
    }
    static PrivateKey DeriveChildSkUnhardened(const PrivateKey& sk, uint32_t index) {
        return CoreMPL::DeriveChildSkUnhardened(sk, index);
    }
    static G1Element DeriveChildPkUnhardened(const G1Element& pk, uint32_t index) {
        return CoreMPL::DeriveChildPkUnhardened(pk, index);
    }
};

}  // end namespace bls

#endif  // SRC_BLSSCHEMES_HPP_
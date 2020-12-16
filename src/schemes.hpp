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

public:
    CoreMPL() = delete;
    CoreMPL(const std::string& strId) : strCiphersuiteId(strId) {}
    // Generates a private key from a seed, similar to HD key generation
    // (hashes the seed), and reduces it mod the group order
    virtual PrivateKey KeyGen(const vector<uint8_t> seed);

    // Generates a public key from a secret key
    virtual vector<uint8_t> SkToPk(const PrivateKey &seckey);

    virtual G1Element SkToG1(const PrivateKey &seckey);

    virtual G2Element Sign(
        const PrivateKey &seckey,
        const vector<uint8_t> &message);

    virtual bool Verify(
        const vector<uint8_t> &pubkey,
        const vector<uint8_t> &message,
        const vector<uint8_t> &signature);

    virtual bool Verify(
        const G1Element &pubkey,
        const vector<uint8_t> &message,
        const G2Element &signature);

    virtual vector<uint8_t> Aggregate(const vector<vector<uint8_t>> &signatures);

    virtual G2Element Aggregate(const vector<G2Element> &signatures);

    virtual G1Element Aggregate(const vector<G1Element> &publicKeys);

    virtual bool AggregateVerify(
        const vector<vector<uint8_t>> &pubkeys,
        const vector<vector<uint8_t>> &messages,
        const vector<uint8_t> &signature);

    virtual bool AggregateVerify(
        const vector<G1Element> &pubkeys,
        const vector<vector<uint8_t>> &messages,
        const G2Element &signature);
    PrivateKey DeriveChildSk(const PrivateKey& sk, uint32_t index);
    PrivateKey DeriveChildSkUnhardened(const PrivateKey& sk, uint32_t index);
    G1Element DeriveChildPkUnhardened(const G1Element& sk, uint32_t index);

protected:
    const std::string& strCiphersuiteId;
    bool NativeVerify(g1_t *pubKeys, g2_t *mappedHashes, size_t length);
};

class BasicSchemeMPL : public CoreMPL {
public:
    static const std::string CIPHERSUITE_ID;
    BasicSchemeMPL() : CoreMPL(BasicSchemeMPL::CIPHERSUITE_ID) {}
    virtual bool AggregateVerify(
            const vector<vector<uint8_t>> &pubkeys,
            const vector<vector<uint8_t>> &messages,
            const vector<uint8_t> &signature) override;

    virtual bool AggregateVerify(
            const vector<G1Element> &pubkeys,
            const vector<vector<uint8_t>> &messages,
            const G2Element &signature) override;
};

class AugSchemeMPL : public CoreMPL {

public:
    static const std::string CIPHERSUITE_ID;
    AugSchemeMPL() : CoreMPL(AugSchemeMPL::CIPHERSUITE_ID) {}

    G2Element Sign(
        const PrivateKey &seckey,
        const vector<uint8_t> &message) override;

    // Used for prepending different augMessage
    G2Element Sign(
            const PrivateKey &seckey,
            const vector<uint8_t> &message,
            const G1Element &prepend_pk);

    virtual bool Verify(
        const vector<uint8_t> &pubkey,
        const vector<uint8_t> &message,
        const vector<uint8_t> &signature) override;

    virtual bool Verify(
        const G1Element &pubkey,
        const vector<uint8_t> &message,
        const G2Element &signature) override;

    virtual bool AggregateVerify(
        const vector<vector<uint8_t>> &pubkeys,
        const vector<vector<uint8_t>> &messages,
        const vector<uint8_t> &signature) override;

    virtual bool AggregateVerify(
        const vector<G1Element> &pubkeys,
        const vector<vector<uint8_t>> &messages,
        const G2Element &signature) override;
};

class PopSchemeMPL : public CoreMPL {

public:
    static const std::string CIPHERSUITE_ID;
    static const std::string POP_CIPHERSUITE_ID;
    PopSchemeMPL() : CoreMPL(PopSchemeMPL::CIPHERSUITE_ID) {}

    G2Element PopProve(const PrivateKey &seckey);

    bool PopVerify(
        const G1Element &pubkey,
        const G2Element &signature_proof);

    bool PopVerify(
        const vector<uint8_t> &pubkey,
        const vector<uint8_t> &proof);

    bool FastAggregateVerify(
        const vector<G1Element> &pubkeys,
        const vector<uint8_t> &message,
        const G2Element &signature);

    bool FastAggregateVerify(
        const vector<vector<uint8_t>> &pubkeys,
        const vector<uint8_t> &message,
        const vector<uint8_t> &signature);
};

}  // end namespace bls

#endif  // SRC_BLSSCHEMES_HPP_
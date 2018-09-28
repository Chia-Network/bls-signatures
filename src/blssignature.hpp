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

#ifndef SRC_BLSSIGNATURE_HPP_
#define SRC_BLSSIGNATURE_HPP_

#include <iostream>
#include <vector>

#include "relic_conf.h"

#if defined GMP && ARITH == GMP
#include <gmp.h>
#endif

#include "blsutil.hpp"
#include "aggregationinfo.hpp"

/**
 * An insecure BLS signature.
 * A BLSSignature is a group element of g2
 * Aggregation of these signatures is not secure on it's own, use BLSSignature instead
 */
class BLSInsecureSignature {
 friend class BLSSignature;
 public:
    static const size_t SIGNATURE_SIZE = 96;

    // Initializes from serialized byte array/
    static BLSInsecureSignature FromBytes(const uint8_t *data);

    // Initializes from native relic g2 element/
    static BLSInsecureSignature FromG2(const relic::g2_t* element);

    // Copy constructor. Deep copies contents.
    BLSInsecureSignature(const BLSInsecureSignature &signature);

    // The following verification methods are all insecure in regard to the rogue public key attack
    bool Verify(const uint8_t* msg, size_t len, const BLSPublicKey& pubKey) const;
    bool VerifyHash(const uint8_t* hash, const BLSPublicKey& pubKey) const;
    bool VerifyAggregated(const std::vector<const uint8_t*>& hashes, const std::vector<BLSPublicKey>& pubKeys) const;

    // Insecurely aggregates signatures
    static BLSInsecureSignature Aggregate(const std::vector<BLSInsecureSignature>& sigs);

    // Insecurely divides signatures
    BLSInsecureSignature DivideBy(const std::vector<BLSInsecureSignature>& sigs) const;

    // Serializes ONLY the 96 byte public key. It does not serialize
    // the aggregation info.
    void Serialize(uint8_t* buffer) const;
    std::vector<uint8_t> Serialize() const;

    friend bool operator==(BLSInsecureSignature const &a, BLSInsecureSignature const &b);
    friend bool operator!=(BLSInsecureSignature const &a, BLSInsecureSignature const &b);
    friend std::ostream &operator<<(std::ostream &os, BLSInsecureSignature const &s);
    BLSInsecureSignature& operator=(const BLSInsecureSignature& rhs);

 private:
    // Prevent public construction, force static method
    BLSInsecureSignature();

    // Exponentiate signature with n
    BLSInsecureSignature Exp(const relic::bn_t n) const;

    static void CompressPoint(uint8_t* result, const relic::g2_t* point);

    // Performs multipairing and checks that everything matches. This is an
    // internal method, only called from VerifyAggregated. It should not be used
    // anywhere else.
    static bool VerifyNative(
            relic::g1_t* pubKeys,
            relic::g2_t* mappedHashes,
            size_t len);

 private:
    // Signature group element
    relic::g2_t sig;
};

/**
 * An encapsulated signature.
 * A BLSSignature is composed of two things:
 *     1. 96 byte group element of g2
 *     2. AggregationInfo object, which describes how the signature was
 *        generated, and how it should be verified.
 */
class BLSSignature {
 public:
    static const size_t SIGNATURE_SIZE = BLSInsecureSignature::SIGNATURE_SIZE;

    // Initializes from serialized byte array/
    static BLSSignature FromBytes(const uint8_t *data);

    // Initializes from bytes with AggregationInfo/
    static BLSSignature FromBytes(const uint8_t *data, const AggregationInfo &info);

    // Initializes from native relic g2 element/
    static BLSSignature FromG2(const relic::g2_t* element);

    // Initializes from native relic g2 element with AggregationInfo/
    static BLSSignature FromG2(const relic::g2_t* element, const AggregationInfo &info);

    // Initializes from insecure signature/
    static BLSSignature FromInsecureSig(const BLSInsecureSignature& sig);

    // Initializes from insecure signature with AggregationInfo/
    static BLSSignature FromInsecureSig(const BLSInsecureSignature& sig, const AggregationInfo &info);

    // Copy constructor. Deep copies contents.
    BLSSignature(const BLSSignature &signature);

    // Verifies a single or aggregate signature.
    // Performs two pairing operations, sig must contain information on
    // how aggregation was performed (AggregationInfo). The Aggregation
    // Info contains all the public keys and messages required.
    bool Verify() const;

    // Securely aggregates many signatures on messages, some of
    // which may be identical. The signature can then be verified
    // using VerifyAggregate. The returned signature contains
    // information on how the aggregation was done (AggragationInfo).
    static BLSSignature AggregateSigs(
            std::vector<BLSSignature> const &sigs);

    // Divides the aggregate signature (this) by a list of signatures.
    // These divisors can be single or aggregate signatures, but all
    // msg/pk pairs in these signatures must be distinct and unique.
    BLSSignature DivideBy(std::vector<BLSSignature> const &divisorSigs) const;

    // Gets the aggregation info on this signature.
    const AggregationInfo* GetAggregationInfo() const;

    // Sets the aggregation information on this signature, which
    // describes how this signature was generated, and how it should
    // be verified.
    void SetAggregationInfo(const AggregationInfo &newAggregationInfo);

    // Serializes ONLY the 96 byte public key. It does not serialize
    // the aggregation info.
    void Serialize(uint8_t* buffer) const;
    std::vector<uint8_t> Serialize() const;

    friend bool operator==(BLSSignature const &a, BLSSignature const &b);
    friend bool operator!=(BLSSignature const &a, BLSSignature const &b);
    friend std::ostream &operator<<(std::ostream &os, BLSSignature const &s);

 private:
    // Prevent public construction, force static method
    BLSSignature() {}

    // Aggregates many signatures using the secure aggregation method.
    // Performs ~ n * 256 g2 operations.
    static BLSSignature AggregateSigsSecure(
            std::vector<BLSSignature> const &sigs,
            std::vector<BLSPublicKey> const &pubKeys,
            std::vector<uint8_t*> const &messageHashes);

    // Internal methods
    static BLSSignature AggregateSigsInternal(
            std::vector<BLSSignature> const &sigs,
            std::vector<std::vector<BLSPublicKey> > const &pubKeys,
            std::vector<std::vector<uint8_t*> > const &messageHashes);

    // Efficiently aggregates many signatures using the simple aggregation
    // method. Performs only n g2 operations.
    static BLSSignature AggregateSigsSimple(
            std::vector<BLSSignature> const &sigs);

 private:
    // internal signature
    BLSInsecureSignature sig;

    // Optional info about how this was aggregated
    AggregationInfo aggregationInfo;
};

#endif  // SRC_BLSSIGNATURE_HPP_

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

#include "blsutil.hpp"
#include "aggregationinfo.hpp"

/**
 * An encapsulated signature.
 * A BLSSignature is composed of two things:
 *     1. 96 byte group element of g2
 *     2. AggregationInfo object, which describes how the signature was
 *        generated, and how it should be verified.
 */
class BLSSignature {
 public:
    static const size_t SIGNATURE_SIZE = 96;

    // Initializes from serialized byte array/
    static BLSSignature FromBytes(const uint8_t *data);

    // Initializes from bytes with AggregationInfo/
    static BLSSignature FromBytes(const uint8_t *data, const AggregationInfo &info);

    // Initializes from native relic g2 element/
    static BLSSignature FromG2(relic::g2_t* element);

    // Copy constructor. Deep copies contents.
    BLSSignature(const BLSSignature &signature);

    // Divides the aggregate signature (this) by a list of signatures.
    // These divisors can be single or aggregate signatures, but all
    // msg/pk pairs in these signatures must be distinct and unique.
    BLSSignature DivideBy(std::vector<BLSSignature> const &divisorSigs) const;

    // Gets the native relic point for this signature.
    void GetPoint(relic::g2_t output) const;

    // Gets the aggregation info on this signature.
    const AggregationInfo* GetAggregationInfo() const;

    // Sets the aggregation information on this signature, which
    // describes how this signature was generated, and how it should
    // be verified.
    void SetAggregationInfo(const AggregationInfo &newAggregationInfo);

    const uint8_t& operator[](size_t pos) const;
    const uint8_t* begin() const;
    const uint8_t* end() const;
    size_t size() const;

    // Serializes ONLY the 96 byte public key. It does not serialize
    // the aggregation info.
    void Serialize(uint8_t* buffer) const;

    friend bool operator==(BLSSignature const &a, BLSSignature const &b);
    friend bool operator!=(BLSSignature const &a, BLSSignature const &b);
    friend bool operator<(BLSSignature const &a,  BLSSignature const &b);
    friend std::ostream &operator<<(std::ostream &os, BLSSignature const &s);
    BLSSignature& operator=(const BLSSignature& rhs);

 private:
    // Prevent public construction, force static method
    BLSSignature() {}

    static void CompressPoint(uint8_t* result, relic::g2_t* point);

    // Signature group element
    relic::g2_t sig;
    uint8_t data[BLSSignature::SIGNATURE_SIZE];

    // Optional info about how this was aggregated
    AggregationInfo aggregationInfo;
};

#endif  // SRC_BLSSIGNATURE_HPP_

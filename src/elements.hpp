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

#ifndef SRC_BLSELEMENTS_HPP_
#define SRC_BLSELEMENTS_HPP_

#include "relic_conf.h"

#if defined GMP && ARITH == GMP
#include <gmp.h>
#endif

namespace bls {
class G1Element {
public:
    static const size_t SIZE = 48;
    static G1Element FromBytes(const uint8_t* bytes);
    static G1Element FromNative(const g1_t* element);

    G1Element(const G1Element &element);
    friend bool operator==(G1Element const &a,  G1Element const &b);
    friend bool operator!=(G1Element const &a,  G1Element const &b);
    friend std::ostream &operator<<(std::ostream &os, G1Element const &s);

    void Serialize(uint8_t *buffer) const;
    std::vector<uint8_t> Serialize() const;
    uint32_t GetFingerprint() const;
    g1_t p;
    G1Element();

private:
    G1Element Exp(const bn_t n) const;
    static void CompressPoint(uint8_t* result, const g1_t* point);
};

class G2Element {
public:
    static const size_t SIZE = 96;
    static G2Element FromBytes(const uint8_t *data);
    static G2Element FromNative(const g2_t* element);
    G2Element(const G2Element &element);

    void Serialize(uint8_t* buffer) const;
    std::vector<uint8_t> Serialize() const;

    friend bool operator==(G2Element const &a, G2Element const &b);
    friend bool operator!=(G2Element const &a, G2Element const &b);
    friend std::ostream &operator<<(std::ostream &os, G2Element const &s);
    G2Element& operator=(const G2Element& rhs);
    g2_t q;

private:
    G2Element();
    G2Element Exp(const bn_t n) const;
    static void CompressPoint(uint8_t* result, const g2_t* point);
};
} // end namespace bls

#endif  // SRC_BLSELEMENTS_HPP_

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

#include <string>
#include <cstring>
#include <algorithm>

#include "bls.hpp"
#include "util.hpp"
#include "privatekey.hpp"
#include "elements.hpp"

namespace bls {
G1Element G1Element::FromBytes(const uint8_t * key) {
    G1Element ele = G1Element();
    uint8_t uncompressed[G1Element::SIZE + 1];
    std::memcpy(uncompressed + 1, key, G1Element::SIZE);
    if (key[0] & 0x80) {
        uncompressed[0] = 0x03;   // Insert extra byte for Y=1
        uncompressed[1] &= 0x7f;  // Remove initial Y bit
    } else {
        uncompressed[0] = 0x02;   // Insert extra byte for Y=0
    }
    g1_read_bin(ele.p, uncompressed, G1Element::SIZE + 1);
    if (g1_is_valid(*(g1_t*)&ele) == 0)
        throw;
    
    // check if inside subgroup
    g1_t point, unity;
    bn_t order;
    bn_null(order);
    bn_new(order);
    g1_null(unity);
    g1_new(unity);

    g1_get_ord(order);
    g1_mul(point, ele.p, order);
    ep_set_infty(unity);
    if (g1_cmp(point, unity) != RLC_EQ)
        throw;
    BLS::CheckRelicErrorsInvalidArgument();
    return ele;
}

G1Element G1Element::FromNative(const g1_t* element) {
    G1Element ele = G1Element();
    g1_copy(ele.p, *element);
    return ele;
}

G1Element::G1Element() {
    g1_set_infty(p);
}

G1Element::G1Element(const G1Element &pubKey) {
    g1_copy(p, pubKey.p);
}

G1Element G1Element::Exp(bn_t const n) const {
    G1Element ret;
    g1_mul(ret.p, const_cast<ep_st*>(p), const_cast<bn_st*>(n));
    return ret;
}

void G1Element::Serialize(uint8_t *buffer) const {
    CompressPoint(buffer, &p);
}

std::vector<uint8_t> G1Element::Serialize() const {
    std::vector<uint8_t> data(G1Element::SIZE);
    Serialize(data.data());
    return data;
}

bool operator==(G1Element const &a,  G1Element const &b) {
    return g1_cmp(a.p, b.p) == RLC_EQ;
}

bool operator!=(G1Element const&a,  G1Element const&b) {
    return !(a == b);
}

std::ostream &operator<<(std::ostream &os, G1Element const &ele) {
    uint8_t data[G1Element::SIZE];
    ele.Serialize(data);
    return os << Util::HexStr(data, G1Element::SIZE);
}

uint32_t G1Element::GetFingerprint() const {
    uint8_t buffer[G1Element::SIZE];
    uint8_t hash[32];
    Serialize(buffer);
    Util::Hash256(hash, buffer, G1Element::SIZE);
    return Util::FourBytesToInt(hash);
}

void G1Element::CompressPoint(uint8_t* result, const g1_t* point) {
    uint8_t buffer[G1Element::SIZE + 1];
    g1_write_bin(buffer, G1Element::SIZE + 1, *point, 1);

    if (buffer[0] == 0x03) {
        buffer[1] |= 0x80;
    }
    std::memcpy(result, buffer + 1, G1Element::SIZE);
}

G2Element G2Element::FromBytes(const uint8_t *data) {
    G2Element ele = G2Element();
    uint8_t uncompressed[G2Element::SIZE + 1];
    std::memcpy(uncompressed + 1, data, G2Element::SIZE);
    if (data[0] & 0x80) {
        uncompressed[0] = 0x03;   // Insert extra byte for Y=1
        uncompressed[1] &= 0x7f;  // Remove initial Y bit
    } else {
        uncompressed[0] = 0x02;   // Insert extra byte for Y=0
    }
    g2_read_bin(ele.q, uncompressed, G2Element::SIZE + 1);
    if (g2_is_valid(*(g2_t*)&ele) == 0)
        throw;

    // check if inside subgroup
    g2_t point, unity;
    bn_t order;
    bn_null(order);
    bn_new(order);
    g2_get_ord(order);
    g2_mul(point, ele.q, order);
    ep2_set_infty(unity);
    if (g2_cmp(point, unity) != RLC_EQ)
        throw;
    BLS::CheckRelicErrorsInvalidArgument();
    return ele;
}

G2Element G2Element::FromNative(const g2_t* element) {
    G2Element ele = G2Element();
    g2_copy(ele.q, *(g2_t*)element);
    return ele;
}

G2Element::G2Element() {
    g2_set_infty(q);
}

G2Element::G2Element(const G2Element &ele) {
    g2_copy(q, *(g2_t*)&ele.q);
}

G2Element G2Element::Exp(const bn_t n) const {
    G2Element result(*this);
    g2_mul(result.q, result.q, const_cast<bn_st*>(n));
    return result;
}

void G2Element::Serialize(uint8_t* buffer) const {
    CompressPoint(buffer, &q);
}

std::vector<uint8_t> G2Element::Serialize() const {
    std::vector<uint8_t> data(G2Element::SIZE);
    Serialize(data.data());
    return data;
}

bool operator==(G2Element const &a, G2Element const &b) {
    return g2_cmp(*(g2_t*)&a.q, *(g2_t*)b.q) == RLC_EQ;
}

bool operator!=(G2Element const &a, G2Element const &b) {
    return !(a == b);
}

std::ostream &operator<<(std::ostream &os, G2Element const &s) {
    uint8_t data[G2Element::SIZE];
    s.Serialize(data);
    return os << Util::HexStr(data, G2Element::SIZE);
}

G2Element& G2Element::operator=(const G2Element &rhs) {
    g2_copy(q, *(g2_t*)&rhs.q);
    return *this;
}

void G2Element::CompressPoint(uint8_t* result, const g2_t* point) {
    uint8_t buffer[G2Element::SIZE + 1];
    g2_write_bin(buffer, G2Element::SIZE + 1, *(g2_t*)point, 1);

    if (buffer[0] == 0x03) {
        buffer[1] |= 0x80;
    }
    std::memcpy(result, buffer + 1, G2Element::SIZE);
}

} // end namespace bls
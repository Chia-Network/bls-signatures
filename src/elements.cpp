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

#include <algorithm>
#include <cstring>
#include <string>

#include "bls.hpp"
#include "elements.hpp"
#include "privatekey.hpp"
#include "util.hpp"

namespace bls {
G1Element G1Element::FromBytes(const uint8_t* bytes)
{
    G1Element ele = G1Element();

    // convert bytes to relic form
    uint8_t buffer[G1Element::SIZE + 1];
    std::memcpy(buffer + 1, bytes, G1Element::SIZE);
    buffer[0] = 0x00;
    buffer[1] &= 0x1f;  // erase 3 msbs from given input

    if ((bytes[0] & 0xc0) == 0xc0) {  // representing infinity
        // enforce that infinity must be 0xc0000..00
        if (bytes[0] != 0xc0) {
            throw std::invalid_argument(
                "Given G1 infinity element must be canonical");
        }
        for (int i = 1; i < G1Element::SIZE; ++i) {
            if (bytes[i] != 0x00) {
                throw std::invalid_argument(
                    "Given G1 infinity element must be canonical");
            }
        }
        return ele;
    } else {
        if ((bytes[0] & 0xc0) != 0x80) {
            throw std::invalid_argument(
                "Given G1 non-infinity element must start with 0b10");
        }

        if (bytes[0] & 0x20) {  // sign bit
            buffer[0] = 0x03;
        } else {
            buffer[0] = 0x02;
        }
    }
    g1_read_bin(ele.p, buffer, G1Element::SIZE + 1);

    if (g1_is_valid(*(g1_t*)&ele) == 0)
        throw std::invalid_argument(
            "Given G1 element failed g1_is_valid check");

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
        throw("Given G1 element failed in_subgroup check");
    try {
        BLS::CheckRelicErrorsInvalidArgument();
    } catch (...) {
        throw("Relic reports invalid argument given");
    }

    return ele;
}

G1Element G1Element::FromByteVector(const std::vector<uint8_t>& bytevec)
{
    return G1Element::FromBytes(bytevec.data());
}

G1Element G1Element::FromNative(const g1_t* element)
{
    G1Element ele = G1Element();
    g1_copy(ele.p, *element);
    return ele;
}

G1Element G1Element::FromBN(const bn_t n)
{
    G1Element ele = G1Element::Generator();
    g1_mul(ele.p, ele.p, const_cast<bn_st*>(n));
    return ele;
}

G1Element G1Element::Generator()
{
    G1Element ele = G1Element();
    g1_get_gen(ele.p);
    return ele;
}

G1Element G1Element::Unity()
{
    G1Element ele = G1Element();
    return ele;
}

G1Element::G1Element()
{
    g1_null(p);
    g1_new(p);
    g1_set_infty(p);
}

G1Element G1Element::FromMessage(
    const std::vector<uint8_t>& message,
    const uint8_t* dst,
    int dst_len)
{
    g1_t ans;
    g1_null(ans);
    g1_new(ans);
    ep_map_dst(ans, message.data(), (int)message.size(), dst, dst_len);
    return G1Element::FromNative(&ans);
}

G1Element::G1Element(const G1Element& pubKey) { g1_copy(p, pubKey.p); }
G1Element& G1Element::operator=(const G1Element& pubKey)
{
    g1_copy(p, pubKey.p);
    return *this;
}

G1Element G1Element::Inverse()
{
    G1Element ans = G1Element();
    bn_t ordMinus1;
    bn_new(ordMinus1);
    g1_get_ord(ordMinus1);
    bn_sub_dig(ordMinus1, ordMinus1, 1);
    g1_mul(ans.p, this->p, ordMinus1);
    return ans;
}

void G1Element::Serialize(uint8_t* buffer) const { CompressPoint(buffer, &p); }

std::vector<uint8_t> G1Element::Serialize() const
{
    std::vector<uint8_t> data(G1Element::SIZE);
    Serialize(data.data());
    return data;
}

bool operator==(G1Element const& a, G1Element const& b)
{
    return g1_cmp(a.p, b.p) == RLC_EQ;
}

bool operator!=(G1Element const& a, G1Element const& b) { return !(a == b); }

std::ostream& operator<<(std::ostream& os, G1Element const& ele)
{
    uint8_t data[G1Element::SIZE];
    ele.Serialize(data);
    return os << Util::HexStr(data, G1Element::SIZE);
}

G1Element& operator+=(G1Element& a, G1Element& b)
{
    g1_add(a.p, a.p, b.p);
    return a;
}

G1Element operator+(G1Element& a, G1Element& b)
{
    g1_t ans;
    g1_new(ans);
    g1_add(ans, a.p, b.p);
    return G1Element::FromNative(&ans);
}

G1Element& operator*=(G1Element& a, bn_t& k)
{
    g1_mul(a.p, a.p, k);
    return a;
}

G1Element operator*(G1Element& a, bn_t& k)
{
    g1_t ans;
    g1_new(ans);
    g1_mul(ans, a.p, k);
    return G1Element::FromNative(&ans);
}

G1Element operator*(bn_t& k, G1Element& a) { return a * k; }

GTElement G1Element::pair(G2Element& b) { return (*this) & b; }

uint32_t G1Element::GetFingerprint() const
{
    uint8_t buffer[G1Element::SIZE];
    uint8_t hash[32];
    Serialize(buffer);
    Util::Hash256(hash, buffer, G1Element::SIZE);
    return Util::FourBytesToInt(hash);
}

void G1Element::CompressPoint(uint8_t* result, const g1_t* point)
{
    uint8_t buffer[G1Element::SIZE + 1];
    g1_write_bin(buffer, G1Element::SIZE + 1, *point, 1);

    if (buffer[0] == 0x03) {  // sign bit set
        buffer[1] |= 0x20;
    } else if (buffer[0] == 0x00) {  // infinity
        std::memset(result, 0, G1Element::SIZE);
        result[0] = 0xc0;
        return;
    }
    buffer[1] |= 0x80;  // indicate compression
    std::memcpy(result, buffer + 1, G1Element::SIZE);
}

// G2Element definitions below

G2Element G2Element::FromBytes(const uint8_t* bytes)
{
    G2Element ele = G2Element();
    uint8_t buffer[G2Element::SIZE + 1];
    std::memcpy(buffer + 1, bytes + G2Element::SIZE / 2, G2Element::SIZE / 2);
    std::memcpy(buffer + 1 + G2Element::SIZE / 2, bytes, G2Element::SIZE / 2);
    buffer[0] = 0x00;
    buffer[49] &= 0x1f;  // erase 3 msbs from input

    if ((bytes[48] & 0xe0) != 0x00) {
        throw std::invalid_argument(
            "Given G2 element must always have 48th byte start with 0b000");
    }
    if (((bytes[0] & 0xc0) == 0xc0)) {  // infinity
        // enforce that infinity must be 0xc0000..00
        if (bytes[0] != 0xc0) {
            throw std::invalid_argument(
                "Given G2 infinity element must be canonical");
        }
        for (int i = 1; i < G2Element::SIZE; ++i) {
            if (bytes[i] != 0x00) {
                throw std::invalid_argument(
                    "Given G2 infinity element must be canonical");
            }
        }
        return ele;
    } else {
        if (((bytes[0] & 0xc0) != 0x80)) {
            throw std::invalid_argument(
                "G2 non-inf element must have 0th byte start with 0b10");
        }
        if (bytes[0] & 0x20) {
            buffer[0] = 0x03;
        } else {
            buffer[0] = 0x02;
        }
    }

    g2_read_bin(ele.q, buffer, G2Element::SIZE + 1);
    if (g2_is_valid(*(g2_t*)&ele) == 0)
        throw std::invalid_argument(
            "Given G2 element failed g2_is_valid check");

    // check if inside subgroup
    g2_t point, unity;
    bn_t order;
    bn_null(order);
    bn_new(order);
    g2_get_ord(order);
    g2_mul(point, ele.q, order);
    ep2_set_infty(unity);
    if (g2_cmp(point, unity) != RLC_EQ)
        throw("Given G2 element failed in_subgroup check");
    try {
        BLS::CheckRelicErrorsInvalidArgument();
    } catch (...) {
        throw("Relic reports invalid argument given");
    }
    return ele;
}

G2Element G2Element::FromByteVector(const std::vector<uint8_t>& bytevec)
{
    return G2Element::FromBytes(bytevec.data());
}

G2Element G2Element::FromNative(const g2_t* element)
{
    G2Element ele = G2Element();
    g2_copy(ele.q, *(g2_t*)element);
    return ele;
}

G2Element G2Element::FromBN(const bn_t n)
{
    G2Element ele = G2Element::Generator();
    g2_mul(ele.q, ele.q, const_cast<bn_st*>(n));
    return ele;
}

G2Element G2Element::Generator()
{
    G2Element ele = G2Element();
    g2_get_gen(ele.q);
    return ele;
}

G2Element G2Element::Inverse()
{
    G2Element ans = G2Element();
    bn_t ordMinus1;
    bn_new(ordMinus1);
    g2_get_ord(ordMinus1);
    bn_sub_dig(ordMinus1, ordMinus1, 1);
    g2_mul(ans.q, this->q, ordMinus1);
    return ans;
}

G2Element G2Element::FromMessage(
    const std::vector<uint8_t>& message,
    const uint8_t* dst,
    int dst_len)
{
    g2_t ans;
    g2_null(ans);
    g2_new(ans);
    ep2_map_dst(ans, message.data(), (int)message.size(), dst, dst_len);
    return G2Element::FromNative(&ans);
}

G2Element::G2Element() { g2_set_infty(q); }

G2Element::G2Element(const G2Element& ele) { g2_copy(q, *(g2_t*)&ele.q); }

void G2Element::Serialize(uint8_t* buffer) const { CompressPoint(buffer, &q); }

std::vector<uint8_t> G2Element::Serialize() const
{
    std::vector<uint8_t> data(G2Element::SIZE);
    Serialize(data.data());
    return data;
}

bool operator==(G2Element const& a, G2Element const& b)
{
    return g2_cmp(*(g2_t*)&a.q, *(g2_t*)b.q) == RLC_EQ;
}

bool operator!=(G2Element const& a, G2Element const& b) { return !(a == b); }

std::ostream& operator<<(std::ostream& os, G2Element const& s)
{
    uint8_t data[G2Element::SIZE];
    s.Serialize(data);
    return os << Util::HexStr(data, G2Element::SIZE);
}

G2Element& operator+=(G2Element& a, G2Element& b)
{
    g2_add(a.q, a.q, b.q);
    return a;
}

G2Element operator+(G2Element& a, G2Element& b)
{
    g2_t ans;
    g2_new(ans);
    g2_add(ans, a.q, b.q);
    return G2Element::FromNative(&ans);
}

G2Element& operator*=(G2Element& a, bn_t& k)
{
    g2_mul(a.q, a.q, k);
    return a;
}

G2Element operator*(G2Element& a, bn_t& k)
{
    g2_t ans;
    g2_new(ans);
    g2_mul(ans, a.q, k);
    return G2Element::FromNative(&ans);
}

G2Element operator*(bn_t& k, G2Element& a) { return a * k; }

GTElement G2Element::pair(G1Element& a) { return a & (*this); }

G2Element& G2Element::operator=(const G2Element& rhs)
{
    g2_copy(q, *(g2_t*)&rhs.q);
    return *this;
}

void G2Element::CompressPoint(uint8_t* result, const g2_t* point)
{
    uint8_t buffer[G2Element::SIZE + 1];
    g2_write_bin(buffer, G2Element::SIZE + 1, *(g2_t*)point, 1);

    if (buffer[0] == 0x00) {  // infinity
        std::memset(result, 0, G2Element::SIZE);
        result[0] = 0xc0;
        return;
    }
    // remove leading 3 bits
    buffer[1] &= 0x1f;
    buffer[49] &= 0x1f;
    if (buffer[0] == 0x03) {
        buffer[49] |= 0xa0;  // swapped later to 0
    } else {
        buffer[49] |= 0x80;
    }

    // Swap buffer
    std::memcpy(result, buffer + 1 + G2Element::SIZE / 2, G2Element::SIZE / 2);
    std::memcpy(result + G2Element::SIZE / 2, buffer + 1, G2Element::SIZE / 2);
}

// GTElement

GTElement::GTElement() { gt_set_unity(r); }

GTElement::GTElement(const GTElement& ele) { gt_copy(r, *(gt_t*)&ele.r); }

GTElement GTElement::FromBytes(const uint8_t* bytes)
{
    GTElement ele = GTElement();
    gt_read_bin(ele.r, bytes, GTElement::SIZE);
    if (gt_is_valid(*(gt_t*)&ele) == 0)
        throw std::invalid_argument("GTElement is invalid");
    BLS::CheckRelicErrorsInvalidArgument();
    return ele;
}

GTElement GTElement::FromByteVector(const std::vector<uint8_t>& bytevec)
{
    return GTElement::FromBytes(bytevec.data());
}

GTElement GTElement::FromNative(const gt_t* element)
{
    GTElement ele = GTElement();
    gt_copy(ele.r, *(gt_t*)element);
    return ele;
}

bool operator==(GTElement const& a, GTElement const& b)
{
    return gt_cmp(*(gt_t*)(a.r), *(gt_t*)(b.r)) == RLC_EQ;
}

bool operator!=(GTElement const& a, GTElement const& b) { return !(a == b); }

std::ostream& operator<<(std::ostream& os, GTElement const& ele)
{
    uint8_t data[GTElement::SIZE];
    ele.Serialize(data);
    return os << Util::HexStr(data, GTElement::SIZE);
}

GTElement operator&(G1Element& a, G2Element& b)
{
    gt_t ans;
    gt_new(ans);
    pp_map_oatep_k12(ans, a.p, b.q);
    return GTElement::FromNative(&ans);
}

void GTElement::Serialize(uint8_t* buffer) const
{
    gt_write_bin(buffer, GTElement::SIZE, *(gt_t*)&r, 1);
}

std::vector<uint8_t> GTElement::Serialize() const
{
    std::vector<uint8_t> data(GTElement::SIZE);
    Serialize(data.data());
    return data;
}

}  // end namespace bls

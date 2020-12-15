// Copyright 2020 Chia Network Inc

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
    ele.CheckValid();
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
    ele.CheckValid();
    return ele;
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
    G1Element ret = G1Element::FromNative(&ans);
    g1_free(ans);
    return ret;
}

G1Element G1Element::Generator()
{
    G1Element ele = G1Element();
    g1_get_gen(ele.p);
    ele.CheckValid();
    return ele;
}

G1Element G1Element::Infinity() {
    G1Element ele = G1Element();
    g1_null(ele.p);
    g1_new(ele.p);
    g1_set_infty(ele.p);
    ele.CheckValid();
    return ele;
}

void G1Element::CheckValid() const {
    if (g1_is_valid(*(g1_t*)&this->p) == 0)
        throw std::invalid_argument(
            "Given G1 element failed g1_is_valid check");

    // check if inside subgroup
    g1_t point, unity, thisP;
    bn_t order;
    bn_new(order);

    g1_get_ord(order);
    g1_copy(thisP, this->p);
    g1_mul(point, thisP, order);
    ep_set_infty(unity);
    if (g1_cmp(point, unity) != RLC_EQ)
        throw std::invalid_argument("Given G1 element failed in_subgroup check");
    bn_free(order);
    BLS::CheckRelicErrors();
}

void G1Element::ToNative(g1_t* output) const {
    g1_copy(*output, this->p);
}

G1Element G1Element::Negate() const
{
    G1Element ans = G1Element();
    g1_neg(ans.p, this->p);
    ans.CheckValid();
    return ans;
}

GTElement G1Element::Pair(const G2Element& b) const { return (*this) & b; }

uint32_t G1Element::GetFingerprint() const
{
    uint8_t buffer[G1Element::SIZE];
    uint8_t hash[32];
    memcpy(buffer, Serialize().data(), G1Element::SIZE);
    Util::Hash256(hash, buffer, G1Element::SIZE);
    return Util::FourBytesToInt(hash);
}


std::vector<uint8_t> G1Element::Serialize() const {
    uint8_t buffer[G1Element::SIZE + 1];
    g1_write_bin(buffer, G1Element::SIZE + 1, this->p, 1);

    if (buffer[0] == 0x00) {  // infinity
        std::vector<uint8_t> result(G1Element::SIZE, 0);
        result[0] = 0xc0;
        return result;
    }

    if (buffer[0] == 0x03) {  // sign bit set
        buffer[1] |= 0x20;
    }

    buffer[1] |= 0x80;  // indicate compression
    std::vector<uint8_t> result(buffer + 1, buffer + 1 + G1Element::SIZE);
    return result;
}

bool operator==(const G1Element & a, const G1Element &b)
{
    return g1_cmp(a.p, b.p) == RLC_EQ;
}

bool operator!=(const G1Element & a, const G1Element & b) { return !(a == b); }

std::ostream& operator<<(std::ostream& os, const G1Element &ele)
{
    return os << Util::HexStr(ele.Serialize());
}

G1Element operator+(const G1Element& a, const G1Element& b)
{
    g1_t ans;
    g1_new(ans);
    g1_add(ans, a.p, b.p);
    G1Element ret = G1Element::FromNative(&ans);
    g1_free(ans);
    return ret;
}

G1Element operator*(const G1Element& a, const bn_t& k)
{
    G1Element nonConstA(a);
    bn_t* nonConstK = Util::SecAlloc<bn_t>(1);
    bn_new(nonConstK[0]);
    bn_copy(nonConstK[0], k);
    g1_t ans;
    g1_new(ans);
    g1_mul(ans, nonConstA.p, nonConstK[0]);
    bn_free(nonConstK[0]);
    Util::SecFree(nonConstK);
    G1Element ret =  G1Element::FromNative(&ans);
    g1_free(ans);
    return ret;
}

G1Element operator*(const bn_t& k, const G1Element& a) { return a * k; }



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
    ele.CheckValid();
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
    ele.CheckValid();
    return ele;
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
    G2Element ret = G2Element::FromNative(&ans);
    g2_free(ans);
    return ret;
}

G2Element G2Element::Generator()
{
    G2Element ele = G2Element();
    g2_get_gen(ele.q);
    ele.CheckValid();
    return ele;
}

G2Element G2Element::Infinity() {
    G2Element ret = G2Element();
    g2_set_infty(ret.q);
    ret.CheckValid();
    return ret;
}

void G2Element::CheckValid() const {
    if (g2_is_valid(*(g2_t*)&this->q) == 0)
        throw std::invalid_argument(
            "Given G2 element failed g2_is_valid check");

    // check if inside subgroup
    g2_t point, unity;
    bn_t order;
    bn_new(order);
    g2_get_ord(order);
    g2_mul(point, *(g2_t*)this->q, order);
    ep2_set_infty(unity);
    if (g2_cmp(point, unity) != RLC_EQ)
        throw std::invalid_argument("Given G2 element failed in_subgroup check");
    bn_free(order);
    BLS::CheckRelicErrors();
}

void G2Element::ToNative(g2_t* output) const {
    g2_copy(*output, *(g2_t*)&this->q);
}

G2Element G2Element::Negate() const
{
    G2Element ans = G2Element();
    G2Element thisCpy(*this);
    g2_neg(ans.q, thisCpy.q);
    ans.CheckValid();
    return ans;
}

GTElement G2Element::Pair(const G1Element& a) const { return a & (*this); }

std::vector<uint8_t> G2Element::Serialize() const {
    uint8_t buffer[G2Element::SIZE + 1];
    g2_write_bin(buffer, G2Element::SIZE + 1, *(g2_t*)this->q, 1);

    if (buffer[0] == 0x00) {  // infinity
        std::vector<uint8_t> result(G2Element::SIZE, 0);
        result[0] = 0xc0;
        return result;
    }

    // remove leading 3 bits
    buffer[1] &= 0x1f;
    buffer[49] &= 0x1f;
    if (buffer[0] == 0x03) {
        buffer[49] |= 0xa0;  // swapped later to 0
    } else {
        buffer[49] |= 0x80;
    }

    // Swap buffer, relic uses the opposite ordering for Fq2 elements
    std::vector<uint8_t> result(G2Element::SIZE, 0);
    std::memcpy(result.data(), buffer + 1 + G2Element::SIZE / 2, G2Element::SIZE / 2);
    std::memcpy(result.data() + G2Element::SIZE / 2, buffer + 1, G2Element::SIZE / 2);
    return result;
}

bool operator==(G2Element const& a, G2Element const& b)
{
    return g2_cmp(*(g2_t*)&a.q, *(g2_t*)b.q) == RLC_EQ;
}

bool operator!=(G2Element const& a, G2Element const& b) { return !(a == b); }

std::ostream& operator<<(std::ostream& os, const G2Element & s)
{
    return os << Util::HexStr(s.Serialize());
}

G2Element operator+(const G2Element& a, const G2Element& b)
{
    G2Element nonConstA(a);
    G2Element nonConstB(b);
    g2_t ans;
    g2_add(ans, nonConstA.q, nonConstB.q);
    return G2Element::FromNative(&ans);
}

G2Element operator*(const G2Element& a, const bn_t& k)
{
    G2Element nonConstA(a);
    g2_t ans;
    bn_t* nonConstK = Util::SecAlloc<bn_t>(1);
    bn_new(nonConstK[0]);
    bn_copy(nonConstK[0], k);
    g2_mul(ans, nonConstA.q, nonConstK[0]);
    bn_free(nonConstK[0]);
    Util::SecFree(nonConstK);
    G2Element ret = G2Element::FromNative(&ans);
    g2_free(ans);
    return ret;
}

G2Element operator*(const bn_t& k, const G2Element& a) { return a * k; }



// GTElement

GTElement GTElement::FromBytes(const uint8_t* bytes)
{
    GTElement ele = GTElement();
    gt_read_bin(ele.r, bytes, GTElement::SIZE);
    if (gt_is_valid(*(gt_t*)&ele) == 0)
        throw std::invalid_argument("GTElement is invalid");
    BLS::CheckRelicErrors();
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

GTElement GTElement::Unity() {
    GTElement ele = GTElement();
    gt_set_unity(ele.r);
    return ele;
}


bool operator==(GTElement const& a, GTElement const& b)
{
    return gt_cmp(*(gt_t*)(a.r), *(gt_t*)(b.r)) == RLC_EQ;
}

bool operator!=(GTElement const& a, GTElement const& b) { return !(a == b); }

std::ostream& operator<<(std::ostream& os, GTElement const& ele)
{
    return os << Util::HexStr(ele.Serialize());
}

GTElement operator&(const G1Element& a, const G2Element& b)
{
    G1Element nonConstA(a);
    gt_t ans;
    gt_new(ans);
    g2_t tmp;
    g2_null(tmp);
    g2_new(tmp);
    b.ToNative(&tmp);
    pp_map_oatep_k12(ans, nonConstA.p, tmp);
    GTElement ret = GTElement::FromNative(&ans);
    gt_free(ans);
    g2_free(tmp);
    return ret;
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

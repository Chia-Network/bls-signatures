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

#include <string.h>

#include <cstring>

#include "bls.hpp"

namespace bls {

const size_t G1Element::SIZE;

G1Element G1Element::FromBytes(Bytes const bytes)
{
    G1Element ele = G1Element::FromBytesUnchecked(bytes);
    ele.CheckValid();
    return ele;
}

G1Element G1Element::FromBytesUnchecked(Bytes const bytes)
{
    if (bytes.size() != SIZE) {
        throw std::invalid_argument("G1Element::FromBytes: Invalid size");
    }

    // check if the element is canonical
    const uint8_t* raw_bytes = bytes.begin();
    bool fZerosOnly =
        Util::HasOnlyZeros(Bytes(raw_bytes + 1, bytes.size() - 1));
    if ((bytes[0] & 0xc0) == 0xc0) {  // representing infinity
        // enforce that infinity must be 0xc0000..00
        if (bytes[0] != 0xc0 || !fZerosOnly) {
            throw std::invalid_argument(
                "Given G1 infinity element must be canonical");
        }
        return G1Element();  // return infinity element (point all zero)
    } else {
        if ((bytes[0] & 0xc0) != 0x80) {
            throw std::invalid_argument(
                "Given G1 non-infinity element must start with 0b10");
        }

        if (fZerosOnly) {
            throw std::invalid_argument(
                "G1 non-infinity element can't have only zeros");
        }
    }

    blst_p1_affine a;
    BLST_ERROR err = blst_p1_uncompress(&a, bytes.begin());
    if (err != BLST_SUCCESS)
        throw std::invalid_argument("G1Element::FromBytes: Invalid bytes");

    return G1Element::FromAffine(a);
}

G1Element G1Element::FromByteVector(const std::vector<uint8_t>& bytevec)
{
    return G1Element::FromBytes(Bytes(bytevec));
}

G1Element G1Element::FromNative(const blst_p1& element)
{
    G1Element ele;
    memcpy(&(ele.p), &element, sizeof(blst_p1));
    return ele;
}

G1Element G1Element::FromAffine(const blst_p1_affine& element)
{
    G1Element ele;
    blst_p1_from_affine(&(ele.p), &element);
    return ele;
}

G1Element G1Element::FromMessage(
    const std::vector<uint8_t>& message,
    const uint8_t* dst,
    int dst_len)
{
    return FromMessage(Bytes(message), dst, dst_len);
}

G1Element G1Element::FromMessage(
    Bytes const message,
    const uint8_t* dst,
    int dst_len)
{
    G1Element ans;
    const byte* aug = nullptr;
    size_t aug_len = 0;

    blst_hash_to_g1(
        &(ans.p),
        message.begin(),
        (int)message.size(),
        dst,
        dst_len,
        aug,
        aug_len);

    assert(ans.IsValid());
    return ans;
}

G1Element G1Element::Generator()
{
    G1Element ele;
    ele.p = *(blst_p1_generator());
    return ele;
}

bool G1Element::IsValid() const
{
    // Infinity no longer valid in Relic
    // https://github.com/relic-toolkit/relic/commit/f3be2babb955cf9f82743e0ae5ef265d3da6c02b
    // if (blst_p1_is_inf(&p) == 1)
    //     return true;

    // return blst_p1_on_curve((blst_p1*)&p);

    if (blst_p1_is_inf(&p))
        return true;

    return blst_p1_in_g1(&p);
}

void G1Element::CheckValid() const
{
    if (!IsValid())
        throw std::invalid_argument("G1 element is invalid");
}

void G1Element::ToNative(blst_p1* output) const
{
    memcpy(output, &p, sizeof(blst_p1));
}

void G1Element::ToAffine(blst_p1_affine* output) const
{
    blst_p1_to_affine(output, &p);
}

G1Element G1Element::Negate() const
{
    G1Element ans;
    ans.FromNative(p);
    blst_p1_cneg(&(ans.p), true);
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

std::vector<uint8_t> G1Element::Serialize() const
{
    uint8_t buffer[G1Element::SIZE];
    blst_p1_compress(buffer, &p);
    return std::vector<uint8_t>(buffer, buffer + G1Element::SIZE);
}

bool operator==(const G1Element& a, const G1Element& b)
{
    return blst_p1_is_equal(&(a.p), &(b.p));
}

bool operator!=(const G1Element& a, const G1Element& b) { return !(a == b); }

std::ostream& operator<<(std::ostream& os, const G1Element& ele)
{
    return os << Util::HexStr(ele.Serialize());
}

G1Element& operator+=(G1Element& a, const G1Element& b)
{
    blst_p1_add(&(a.p), &(a.p), &(b.p));
    return a;
}

G1Element operator+(const G1Element& a, const G1Element& b)
{
    G1Element ans;
    blst_p1_add(&(ans.p), &(a.p), &(b.p));
    return ans;
}

G1Element operator*(const G1Element& a, const blst_scalar& k)
{
    G1Element ans;
    byte* bte = Util::SecAlloc<byte>(32);
    blst_bendian_from_scalar(bte, &k);
    blst_p1_mult(&(ans.p), &(a.p), bte, 256);
    Util::SecFree(bte);

    return ans;
}

G1Element operator*(const blst_scalar& k, const G1Element& a) { return a * k; }

// G2Element definitions below

const size_t G2Element::SIZE;

G2Element G2Element::FromBytes(Bytes const bytes)
{
    G2Element ele = G2Element::FromBytesUnchecked(bytes);
    ele.CheckValid();
    return ele;
}

G2Element G2Element::FromBytesUnchecked(Bytes const bytes)
{
    if (bytes.size() != SIZE) {
        throw std::invalid_argument("G2Element::FromBytes: Invalid size");
    }

    blst_p2_affine a;
    BLST_ERROR err = blst_p2_uncompress(&a, bytes.begin());
    if (err != BLST_SUCCESS)
        throw std::invalid_argument("G2Element::FromBytes: Invalid bytes");

    return G2Element::FromAffine(a);
}

G2Element G2Element::FromByteVector(const std::vector<uint8_t>& bytevec)
{
    return G2Element::FromBytes(Bytes(bytevec));
}

G2Element G2Element::FromNative(const blst_p2& element)
{
    G2Element ele;
    memcpy(&(ele.q), &element, sizeof(blst_p2));
    return ele;
}

G2Element G2Element::FromAffine(const blst_p2_affine& element)
{
    G2Element ele;
    blst_p2_from_affine(&(ele.q), &element);
    return ele;
}

G2Element G2Element::FromMessage(
    const std::vector<uint8_t>& message,
    const uint8_t* dst,
    int dst_len)
{
    return FromMessage(Bytes(message), dst, dst_len);
}

G2Element G2Element::FromMessage(
    Bytes const message,
    const uint8_t* dst,
    int dst_len)
{
    G2Element ans;
    const byte* aug = nullptr;
    size_t aug_len = 0;

    blst_hash_to_g2(
        &(ans.q),
        message.begin(),
        (int)message.size(),
        dst,
        dst_len,
        aug,
        aug_len);

    assert(ans.IsValid());
    return ans;
}

G2Element G2Element::Generator()
{
    G2Element ele;
    ele.q = (*blst_p2_generator());
    return ele;
}

bool G2Element::IsValid() const
{
    // Infinity no longer valid in Relic
    // https://github.com/relic-toolkit/relic/commit/f3be2babb955cf9f82743e0ae5ef265d3da6c02b
    // if (blst_p2_is_inf(&q) == 1)
    //     return true;

    // return blst_p2_on_curve((blst_p2*)&q);

    if (blst_p2_is_inf(&q))
        return true;

    return blst_p2_in_g2(&q);
}

void G2Element::CheckValid() const
{
    if (!IsValid())
        throw std::invalid_argument("G2 element is invalid");
}

void G2Element::ToNative(blst_p2* output) const
{
    memcpy(output, (blst_p2*)&q, sizeof(blst_p2));
}

void G2Element::ToAffine(blst_p2_affine* output) const
{
    blst_p2_to_affine(output, &q);
}

G2Element G2Element::Negate() const
{
    G2Element ans;
    ans.FromNative(q);
    blst_p2_cneg(&(ans.q), true);
    return ans;
}

GTElement G2Element::Pair(const G1Element& a) const { return a & (*this); }

std::vector<uint8_t> G2Element::Serialize() const
{
    uint8_t buffer[G2Element::SIZE];
    blst_p2_compress(buffer, &q);
    return std::vector<uint8_t>(buffer, buffer + G2Element::SIZE);
}

bool operator==(G2Element const& a, G2Element const& b)
{
    return blst_p2_is_equal(&(a.q), &(b.q));
}

bool operator!=(G2Element const& a, G2Element const& b) { return !(a == b); }

std::ostream& operator<<(std::ostream& os, const G2Element& s)
{
    return os << Util::HexStr(s.Serialize());
}

G2Element& operator+=(G2Element& a, const G2Element& b)
{
    blst_p2_add(&(a.q), &(a.q), &(b.q));
    return a;
}

G2Element operator+(const G2Element& a, const G2Element& b)
{
    G2Element ans;
    blst_p2_add(&(ans.q), &(a.q), &(b.q));
    return ans;
}

G2Element operator*(const G2Element& a, const blst_scalar& k)
{
    G2Element ans;
    byte* bte = Util::SecAlloc<byte>(32);
    blst_bendian_from_scalar(bte, &k);
    blst_p2_mult(&(ans.q), &(a.q), bte, 256);
    Util::SecFree(bte);

    return ans;
}

G2Element operator*(const blst_scalar& k, const G2Element& a) { return a * k; }

// GTElement

const size_t GTElement::SIZE;

/*
 * Currently deserliazation is not available - these are currently
 * broken and just return the zero element
 */
GTElement GTElement::FromBytes(Bytes const bytes)
{
    GTElement ele = GTElement::FromBytesUnchecked(bytes);
    //
    // this doesn't seem to be the proper check as it doesn't work as expeced
    //
    // if (!blst_fp12_in_group(&(ele.r)))
    //     throw std::invalid_argument("GTElement is invalid");
    return ele;
}

GTElement GTElement::FromBytesUnchecked(Bytes const bytes)
{
    if (bytes.size() != SIZE) {
        throw std::invalid_argument("GTElement::FromBytes: Invalid size");
    }
    GTElement ele = GTElement();
    // TO DO  blst_fp12_from_bendian(&(ele.r), bytes.begin());
    return ele;
}

GTElement GTElement::FromByteVector(const std::vector<uint8_t>& bytevec)
{
    return GTElement::FromBytes(Bytes(bytevec));
}

GTElement GTElement::FromNative(const blst_fp12* element)
{
    GTElement ele = GTElement();
    ele.r = *element;
    return ele;
}

GTElement GTElement::FromAffine(const blst_p1_affine& affine)
{
    GTElement ele = GTElement();
    blst_aggregated_in_g1(&ele.r, &affine);
    return ele;
}

GTElement GTElement::FromAffine(const blst_p2_affine& affine)
{
    GTElement ele = GTElement();
    blst_aggregated_in_g2(&ele.r, &affine);
    return ele;
}

GTElement GTElement::Unity()
{
    GTElement ele = GTElement();
    ele.FromNative(blst_fp12_one());
    return ele;
}

bool operator==(GTElement const& a, GTElement const& b)
{
    return blst_fp12_is_equal(&(a.r), &(b.r));
}

bool operator!=(GTElement const& a, GTElement const& b) { return !(a == b); }

std::ostream& operator<<(std::ostream& os, GTElement const& ele)
{
    return os << Util::HexStr(ele.Serialize());
}

GTElement operator&(const G1Element& a, const G2Element& b)
{
    blst_fp12 ans;

    blst_p1_affine aff1;
    blst_p2_affine aff2;
    a.ToAffine(&aff1);
    b.ToAffine(&aff2);

    blst_miller_loop(&ans, &aff2, &aff1);
    blst_final_exp(&ans, &ans);

    GTElement ret = GTElement::FromNative(&ans);

    return ret;
}

GTElement operator*(GTElement& a, GTElement& b)
{
    GTElement ans;
    blst_fp12_mul(&(ans.r), &(a.r), &(b.r));
    return ans;
}

void GTElement::Serialize(uint8_t* buffer) const
{
    blst_bendian_from_fp12(buffer, &r);
}

std::vector<uint8_t> GTElement::Serialize() const
{
    std::vector<uint8_t> data(GTElement::SIZE);
    Serialize(data.data());
    return data;
}

}  // end namespace bls

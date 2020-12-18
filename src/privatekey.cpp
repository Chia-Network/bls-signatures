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
#include <cassert>
#include <cstring>
#include <string>

#include "bls.hpp"
#include "elements.hpp"
#include "hkdf.hpp"
#include "privatekey.hpp"
#include "util.hpp"

namespace bls {

// Construct a private key from a bytearray.
PrivateKey PrivateKey::FromBytes(const uint8_t *bytes, bool modOrder)
{
    PrivateKey k;
    k.AllocateKeyData();
    bn_read_bin(*k.keydata, bytes, PrivateKey::PRIVATE_KEY_SIZE);
    bn_t ord;
    bn_new(ord);
    g1_get_ord(ord);
    if (modOrder) {
        bn_mod_basic(*k.keydata, *k.keydata, ord);
    } else {
        if (bn_cmp(*k.keydata, ord) > 0) {
            throw std::invalid_argument(
                "PrivateKey byte data must be less than the group order");
        }
    }
    return k;
}

// Construct a private key from a bytearray.
PrivateKey PrivateKey::FromByteVector(const std::vector<uint8_t> bytes, bool modOrder)
{
    if (bytes.size() != PrivateKey::PRIVATE_KEY_SIZE) {
        throw std::invalid_argument("Private keys must be 32 bytes");
    }
    return PrivateKey::FromBytes(bytes.data(), modOrder);
}

// Construct a private key from another private key.
PrivateKey::PrivateKey(const PrivateKey &privateKey)
{
    AllocateKeyData();
    bn_copy(*keydata, *privateKey.keydata);
}

PrivateKey::PrivateKey(PrivateKey &&k)
    : keydata(std::exchange(k.keydata, nullptr))
{}

PrivateKey::~PrivateKey() { if(keydata !=NULL) Util::SecFree(keydata); }

G1Element PrivateKey::GetG1Element() const
{
    g1_t *p = Util::SecAlloc<g1_t>(1);
    g1_mul_gen(*p, *keydata);

    const G1Element ret = G1Element::FromNative(p);
    Util::SecFree(*p);
    return ret;
}

G2Element PrivateKey::GetG2Element() const
{
    g2_t *q = Util::SecAlloc<g2_t>(1);
    g2_mul_gen(*q, *keydata);

    const G2Element ret = G2Element::FromNative(q);
    Util::SecFree(*q);
    return ret;
}

G1Element operator*(const G1Element &a, const PrivateKey &k)
{
    g1_t ans;
    a.ToNative(&ans);
    g1_mul(ans, ans, *(k.keydata));
    return G1Element::FromNative(&ans);
}

G1Element operator*(const PrivateKey &k, const G1Element &a) { return a * k; }

G2Element operator*(const G2Element &a, const PrivateKey &k)
{
    g2_t ans;
    a.ToNative(&ans);
    g2_mul(ans, ans, *(k.keydata));
    return G2Element::FromNative(&ans);
}

G2Element operator*(const PrivateKey &k, const G2Element &a) { return a * k; }

G2Element PrivateKey::GetG2Power(const G2Element& element) const
{
    g2_t *q = Util::SecAlloc<g2_t>(1);
    element.ToNative(q);
    g2_mul(*q, *q, *keydata);

    const G2Element ret = G2Element::FromNative(q);
    Util::SecFree(*q);
    return ret;
}

PrivateKey PrivateKey::Aggregate(std::vector<PrivateKey> const &privateKeys)
{
    if (privateKeys.empty()) {
        throw std::length_error("Number of private keys must be at least 1");
    }

    bn_t order;
    bn_new(order);
    g1_get_ord(order);

    PrivateKey ret(privateKeys[0]);
    for (size_t i = 1; i < privateKeys.size(); i++) {
        bn_add(*ret.keydata, *ret.keydata, *privateKeys[i].keydata);
        bn_mod_basic(*ret.keydata, *ret.keydata, order);
    }
    return ret;
}

bool PrivateKey::IsZero() const { return (bn_is_zero(*keydata)); }

bool operator==(const PrivateKey &a, const PrivateKey &b)
{
    return bn_cmp(*a.keydata, *b.keydata) == RLC_EQ;
}

bool operator!=(const PrivateKey &a, const PrivateKey &b) { return !(a == b); }

void PrivateKey::Serialize(uint8_t *buffer) const
{
    bn_write_bin(buffer, PrivateKey::PRIVATE_KEY_SIZE, *keydata);
}

std::vector<uint8_t> PrivateKey::Serialize() const
{
    std::vector<uint8_t> data(PRIVATE_KEY_SIZE);
    Serialize(data.data());
    return data;
}

G2Element PrivateKey::SignG2(
    const uint8_t *msg,
    size_t len,
    const uint8_t *dst,
    size_t dst_len) const
{
    g2_t pt;
    g2_new(pt);

    ep2_map_dst(pt, msg, len, dst, dst_len);
    g2_mul(pt, pt, *keydata);
    return G2Element::FromNative(&pt);
}

void PrivateKey::AllocateKeyData()
{
    assert(!keydata);
    keydata = Util::SecAlloc<bn_t>(1);
    bn_new(*keydata);  // Freed in destructor
    bn_zero(*keydata);
}
}  // end namespace bls

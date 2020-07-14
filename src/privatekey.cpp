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
#include <cassert>
#include <cstring>
#include <string>

#include "bls.hpp"
#include "elements.hpp"
#include "hkdf.hpp"
#include "privatekey.hpp"
#include "util.hpp"

namespace bls {
PrivateKey PrivateKey::FromSeed(const uint8_t *seed, size_t seedLen)
{
    // KeyGen
    // 1. PRK = HKDF-Extract("BLS-SIG-KEYGEN-SALT-", IKM || I2OSP(0, 1))
    // 2. OKM = HKDF-Expand(PRK, keyInfo || I2OSP(L, 2), L)
    // 3. SK = OS2IP(OKM) mod r
    // 4. return SK

    const uint8_t info[1] = {0};
    const size_t infoLen = 0;

    // Required by the ietf spec to be at least 32 bytes
    assert(seedLen >= 32);

    // "BLS-SIG-KEYGEN-SALT-" in ascii
    const uint8_t saltHkdf[20] = {66, 76, 83, 45, 83, 73, 71, 45, 75, 69,
                                  89, 71, 69, 78, 45, 83, 65, 76, 84, 45};

    uint8_t *prk = Util::SecAlloc<uint8_t>(32);
    uint8_t *ikmHkdf = Util::SecAlloc<uint8_t>(seedLen + 1);
    memcpy(ikmHkdf, seed, seedLen);
    ikmHkdf[seedLen] = 0;

    const uint8_t L = 48;  // `ceil((3 * ceil(log2(r))) / 16)`, where `r` is the
                           // order of the BLS 12-381 curve

    uint8_t *okmHkdf = Util::SecAlloc<uint8_t>(L);

    uint8_t keyInfoHkdf[infoLen + 2];
    memcpy(keyInfoHkdf, info, infoLen);
    keyInfoHkdf[infoLen] = 0;  // Two bytes for L, 0 and 48
    keyInfoHkdf[infoLen + 1] = L;

    HKDF256::ExtractExpand(
        okmHkdf,
        L,
        ikmHkdf,
        seedLen + 1,
        saltHkdf,
        20,
        keyInfoHkdf,
        infoLen + 2);

    bn_t order;
    bn_new(order);
    g1_get_ord(order);

    // Make sure private key is less than the curve order
    bn_t *skBn = Util::SecAlloc<bn_t>(1);
    bn_new(*skBn);
    bn_read_bin(*skBn, okmHkdf, L);
    bn_mod_basic(*skBn, *skBn, order);

    PrivateKey k;
    k.AllocateKeyData();
    bn_copy(*k.keydata, *skBn);

    bn_free(order);
    bn_free(skBn);
    Util::SecFree(prk);
    Util::SecFree(ikmHkdf);
    Util::SecFree(skBn);
    Util::SecFree(okmHkdf);

    return k;
}

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

PrivateKey PrivateKey::FromBN(bn_t sk)
{
    PrivateKey k;
    k.AllocateKeyData();
    bn_copy(*k.keydata, sk);
    return k;
}

// Construct a private key from another private key.
PrivateKey::PrivateKey(const PrivateKey &privateKey)
{
    AllocateKeyData();
    bn_copy(*keydata, *privateKey.keydata);
}

PrivateKey::PrivateKey(PrivateKey &&k) { std::swap(keydata, k.keydata); }

PrivateKey::~PrivateKey() { Util::SecFree(keydata); }

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

G1Element &operator*=(G1Element &a, PrivateKey &k)
{
    g1_mul(a.p, a.p, *(k.keydata));
    return a;
}

G1Element &operator*=(PrivateKey &k, G1Element &a)
{
    a *= k;
    return a;
}

G1Element operator*(G1Element &a, PrivateKey &k)
{
    g1_t ans;
    g1_new(ans);
    g1_mul(ans, a.p, *(k.keydata));
    return G1Element::FromNative(&ans);
}

G1Element operator*(PrivateKey &k, G1Element &a) { return a * k; }

G2Element &operator*=(G2Element &a, PrivateKey &k)
{
    g2_mul(a.q, a.q, *(k.keydata));
    return a;
}

G2Element &operator*=(PrivateKey &k, G2Element &a)
{
    a *= k;
    return a;
}

G2Element operator*(G2Element &a, PrivateKey &k)
{
    g2_t ans;
    g2_new(ans);
    g2_mul(ans, a.q, *(k.keydata));
    return G2Element::FromNative(&ans);
}

G2Element operator*(PrivateKey &k, G2Element &a) { return a * k; }

G2Element PrivateKey::GetG2Power(g2_t base) const
{
    g2_t *q = Util::SecAlloc<g2_t>(1);
    g2_mul(*q, base, *keydata);

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

bool PrivateKey::IsZero() { return (bn_is_zero(*keydata)); }

PrivateKey PrivateKey::Mul(const bn_t n) const
{
    bn_t order;
    bn_new(order);
    g2_get_ord(order);

    PrivateKey ret;
    ret.AllocateKeyData();
    bn_mul_comba(*ret.keydata, *keydata, n);
    bn_mod_basic(*ret.keydata, *ret.keydata, order);
    return ret;
}

bool operator==(const PrivateKey &a, const PrivateKey &b)
{
    return bn_cmp(*a.keydata, *b.keydata) == RLC_EQ;
}

bool operator!=(const PrivateKey &a, const PrivateKey &b) { return !(a == b); }

PrivateKey &PrivateKey::operator=(const PrivateKey &rhs)
{
    Util::SecFree(keydata);
    AllocateKeyData();
    bn_copy(*keydata, *rhs.keydata);
    return *this;
}

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
    keydata = Util::SecAlloc<bn_t>(1);
    bn_new(*keydata);  // Freed in destructor
    bn_zero(*keydata);
}
}  // end namespace bls

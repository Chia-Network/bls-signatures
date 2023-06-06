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

#include "bls.hpp"

namespace bls {

const size_t PrivateKey::PRIVATE_KEY_SIZE;

// Construct a private key from a bytearray.
PrivateKey PrivateKey::FromBytes(const Bytes &bytes, bool modOrder)
{
    if (bytes.size() != PRIVATE_KEY_SIZE) {
        throw std::invalid_argument("PrivateKey::FromBytes: Invalid size");
    }

    PrivateKey k;
    if (modOrder)
        // this allows any bytes to be input and does proper mod order
        blst_scalar_from_be_bytes(k.keydata, bytes.begin(), bytes.size());
    else
        // this should only be the output of deserialization
        blst_scalar_from_bendian(k.keydata, bytes.begin());

    if (Util::HasOnlyZeros(bytes)) {
        return k;  // don't check anything else, we allow zero private key
    }

    if (!blst_sk_check(k.keydata))
        throw std::invalid_argument(
            "PrivateKey byte data must be less than the group order");

    return k;
}

// Construct a private key from a bytearray.
PrivateKey PrivateKey::FromByteVector(
    const std::vector<uint8_t> bytes,
    bool modOrder)
{
    return PrivateKey::FromBytes(Bytes(bytes), modOrder);
}

PrivateKey::PrivateKey() { AllocateKeyData(); };

// Construct a private key from another private key.
PrivateKey::PrivateKey(const PrivateKey &privateKey)
{
    privateKey.CheckKeyData();
    AllocateKeyData();
    memcpy(keydata, privateKey.keydata, 32);
}

PrivateKey::PrivateKey(PrivateKey &&k)
    : keydata(std::exchange(k.keydata, nullptr))
{
    k.InvalidateCaches();
}

PrivateKey::~PrivateKey() { DeallocateKeyData(); }

void PrivateKey::DeallocateKeyData()
{
    if (keydata != nullptr) {
        Util::SecFree(keydata);
        keydata = nullptr;
    }
    InvalidateCaches();
}

void PrivateKey::InvalidateCaches()
{
    fG1CacheValid = false;
    fG2CacheValid = false;
}

PrivateKey &PrivateKey::operator=(const PrivateKey &other)
{
    CheckKeyData();
    other.CheckKeyData();
    InvalidateCaches();
    memcpy(keydata, other.keydata, 32);
    return *this;
}

PrivateKey &PrivateKey::operator=(PrivateKey &&other)
{
    DeallocateKeyData();
    keydata = std::exchange(other.keydata, nullptr);
    other.InvalidateCaches();
    return *this;
}

const G1Element &PrivateKey::GetG1Element() const
{
    if (!fG1CacheValid) {
        CheckKeyData();
        blst_p1 *p = Util::SecAlloc<blst_p1>(1);
        blst_sk_to_pk_in_g1(p, keydata);

        g1Cache = G1Element::FromNative(*p);
        Util::SecFree(p);
        fG1CacheValid = true;
    }
    return g1Cache;
}

const G2Element &PrivateKey::GetG2Element() const
{
    if (!fG2CacheValid) {
        CheckKeyData();
        blst_p2 *q = Util::SecAlloc<blst_p2>(1);
        blst_sk_to_pk_in_g2(q, keydata);

        g2Cache = G2Element::FromNative(*q);
        Util::SecFree(q);
        fG2CacheValid = true;
    }
    return g2Cache;
}

G1Element operator*(const G1Element &a, const PrivateKey &k)
{
    k.CheckKeyData();

    blst_p1 *ans = Util::SecAlloc<blst_p1>(1);
    a.ToNative(ans);
    byte *bte = Util::SecAlloc<byte>(32);
    blst_bendian_from_scalar(bte, k.keydata);
    blst_p1_mult(ans, ans, bte, 256);
    G1Element ret = G1Element::FromNative(*ans);
    Util::SecFree(ans);
    Util::SecFree(bte);
    return ret;
}

G1Element operator*(const PrivateKey &k, const G1Element &a) { return a * k; }

G2Element operator*(const G2Element &a, const PrivateKey &k)
{
    k.CheckKeyData();
    blst_p2 *ans = Util::SecAlloc<blst_p2>(1);
    a.ToNative(ans);
    byte *bte = Util::SecAlloc<byte>(32);
    blst_bendian_from_scalar(bte, k.keydata);
    blst_p2_mult(ans, ans, bte, 256);
    G2Element ret = G2Element::FromNative(*ans);
    Util::SecFree(ans);
    Util::SecFree(bte);
    return ret;
}

G2Element operator*(const PrivateKey &k, const G2Element &a) { return a * k; }

G2Element PrivateKey::GetG2Power(const G2Element &element) const
{
    CheckKeyData();
    blst_p2 *q = Util::SecAlloc<blst_p2>(1);
    element.ToNative(q);
    byte *bte = Util::SecAlloc<byte>(32);
    blst_bendian_from_scalar(bte, keydata);
    blst_p2_mult(q, q, bte, 255);
    const G2Element ret = G2Element::FromNative(*q);
    Util::SecFree(q);
    Util::SecFree(bte);
    return ret;
}

PrivateKey PrivateKey::Aggregate(std::vector<PrivateKey> const &privateKeys)
{
    if (privateKeys.empty()) {
        throw std::length_error("Number of private keys must be at least 1");
    }

    PrivateKey ret;
    assert(ret.IsZero());
    for (size_t i = 0; i < privateKeys.size(); i++) {
        privateKeys[i].CheckKeyData();
        blst_sk_add_n_check(ret.keydata, ret.keydata, privateKeys[i].keydata);
    }
    return ret;
}

bool PrivateKey::IsZero() const
{
    CheckKeyData();
    blst_scalar zro;
    memset(&zro, 0x00, sizeof(blst_scalar));

    return memcmp(keydata, &zro, 32) == 0;
}

bool operator==(const PrivateKey &a, const PrivateKey &b)
{
    a.CheckKeyData();
    b.CheckKeyData();
    return memcmp(a.keydata, b.keydata, sizeof(blst_scalar)) == 0;
}

bool operator!=(const PrivateKey &a, const PrivateKey &b) { return !(a == b); }

void PrivateKey::Serialize(uint8_t *buffer) const
{
    if (buffer == nullptr) {
        throw std::runtime_error("PrivateKey::Serialize buffer invalid");
    }
    CheckKeyData();
    blst_bendian_from_scalar(buffer, keydata);
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
    CheckKeyData();

    blst_p2 *pt = Util::SecAlloc<blst_p2>(1);

    blst_hash_to_g2(pt, msg, len, dst, dst_len, nullptr, 0);
    blst_sign_pk_in_g1(pt, pt, keydata);

    G2Element ret = G2Element::FromNative(*pt);
    Util::SecFree(pt);
    return ret;
}

void PrivateKey::AllocateKeyData()
{
    assert(!keydata);
    keydata = Util::SecAlloc<blst_scalar>(1);
    memset(keydata, 0x00, sizeof(blst_scalar));
}

void PrivateKey::CheckKeyData() const
{
    if (keydata == nullptr) {
        throw std::runtime_error(
            "PrivateKey::CheckKeyData keydata not initialized");
    }
}

}  // end namespace bls

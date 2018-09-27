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

#include <iostream>
#include <cstring>
#include <algorithm>

#include "blspublickey.hpp"
#include "blsutil.hpp"
#include "bls.hpp"

BLSPublicKey BLSPublicKey::FromBytes(const uint8_t * key) {
    BLS::AssertInitialized();
    BLSPublicKey pk = BLSPublicKey();
    uint8_t uncompressed[PUBLIC_KEY_SIZE + 1];
    std::memcpy(uncompressed + 1, key, PUBLIC_KEY_SIZE);
    if (key[0] & 0x80) {
        uncompressed[0] = 0x03;   // Insert extra byte for Y=1
        uncompressed[1] &= 0x7f;  // Remove initial Y bit
    } else {
        uncompressed[0] = 0x02;   // Insert extra byte for Y=0
    }
    relic::g1_read_bin(pk.q, uncompressed, PUBLIC_KEY_SIZE + 1);
    return pk;
}

BLSPublicKey BLSPublicKey::FromG1(const relic::g1_t* pubKey) {
    BLS::AssertInitialized();
    BLSPublicKey pk = BLSPublicKey();
    g1_copy(pk.q, *pubKey);
    return pk;
}

BLSPublicKey::BLSPublicKey() {
    BLS::AssertInitialized();
    g1_set_infty(q);
}

BLSPublicKey::BLSPublicKey(const BLSPublicKey &pubKey) {
    BLS::AssertInitialized();
    g1_copy(q, pubKey.q);
}

BLSPublicKey BLSPublicKey::AggregateInsecure(std::vector<BLSPublicKey> const& pubKeys) {
    if (pubKeys.empty()) {
        throw std::string("Number of public keys must be at least 1");
    }

    BLSPublicKey ret = pubKeys[0];
    for (size_t i = 1; i < pubKeys.size(); i++) {
        g1_add(ret.q, ret.q, pubKeys[i].q);
    }
    return ret;
}

BLSPublicKey BLSPublicKey::Aggregate(std::vector<BLSPublicKey> const& pubKeys) {
    if (pubKeys.size() < 1) {
        throw std::string("Number of public keys must be at least 1");
    }

    std::vector<uint8_t*> serPubKeys(pubKeys.size());
    for (size_t i = 0; i < pubKeys.size(); i++) {
        serPubKeys[i] = new uint8_t[BLSPublicKey::PUBLIC_KEY_SIZE];
        pubKeys[i].Serialize(serPubKeys[i]);
    }

    // Sort the public keys by public key
    std::vector<size_t> pubKeysSorted(pubKeys.size());
    for (size_t i = 0; i < pubKeysSorted.size(); i++) {
        pubKeysSorted[i] = i;
    }

    std::sort(pubKeysSorted.begin(), pubKeysSorted.end(), [&serPubKeys](size_t a, size_t b) {
        return memcmp(serPubKeys[a], serPubKeys[b], BLSPublicKey::PUBLIC_KEY_SIZE) < 0;
    });

    relic::bn_t *computedTs = new relic::bn_t[pubKeysSorted.size()];
    for (size_t i = 0; i < pubKeysSorted.size(); i++) {
        bn_new(computedTs[i]);
    }
    BLS::HashPubKeys(computedTs, pubKeysSorted.size(), serPubKeys, pubKeysSorted);

    // Raise all keys to power of the corresponding t's and aggregate the results into aggKey
    std::vector<BLSPublicKey> expKeys;
    expKeys.reserve(pubKeysSorted.size());
    for (size_t i = 0; i < pubKeysSorted.size(); i++) {
        const BLSPublicKey& pk = pubKeys[pubKeysSorted[i]];
        expKeys.emplace_back(pk.Exp(computedTs[i]));
    }
    BLSPublicKey aggKey = BLSPublicKey::AggregateInsecure(expKeys);

    for (size_t i = 0; i < pubKeysSorted.size(); i++) {
        bn_free(computedTs[i]);
    }
    for (auto p : serPubKeys) {
        delete[] p;
    }
    delete[] computedTs;

    BLS::CheckRelicErrors();
    return aggKey;
}

BLSPublicKey BLSPublicKey::Exp(relic::bn_t const n) const {
    BLSPublicKey ret;
    g1_mul(ret.q, q, n);
    return ret;
}

void BLSPublicKey::Serialize(uint8_t *buffer) const {
    BLS::AssertInitialized();
    CompressPoint(buffer, &q);
}

std::vector<uint8_t> BLSPublicKey::Serialize() const {
    std::vector<uint8_t> data(PUBLIC_KEY_SIZE);
    Serialize(data.data());
    return data;
}

// Comparator implementation.
bool operator==(BLSPublicKey const &a,  BLSPublicKey const &b) {
    BLS::AssertInitialized();
    return g1_cmp(a.q, b.q) == CMP_EQ;
}

bool operator!=(BLSPublicKey const&a,  BLSPublicKey const&b) {
    return !(a == b);
}

std::ostream &operator<<(std::ostream &os, BLSPublicKey const &pk) {
    BLS::AssertInitialized();
    uint8_t data[BLSPublicKey::PUBLIC_KEY_SIZE];
    pk.Serialize(data);
    return os << BLSUtil::HexStr(data, BLSPublicKey::PUBLIC_KEY_SIZE);
}

uint32_t BLSPublicKey::GetFingerprint() const {
    BLS::AssertInitialized();
    uint8_t buffer[BLSPublicKey::PUBLIC_KEY_SIZE];
    uint8_t hash[32];
    Serialize(buffer);
    BLSUtil::Hash256(hash, buffer, BLSPublicKey::PUBLIC_KEY_SIZE);
    return BLSUtil::FourBytesToInt(hash);
}

void BLSPublicKey::CompressPoint(uint8_t* result, const relic::g1_t* point) {
    uint8_t buffer[BLSPublicKey::PUBLIC_KEY_SIZE + 1];
    g1_write_bin(buffer, BLSPublicKey::PUBLIC_KEY_SIZE + 1, *point, 1);

    if (buffer[0] == 0x03) {
        buffer[1] |= 0x80;
    }
    std::memcpy(result, buffer + 1, PUBLIC_KEY_SIZE);
}

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
#include "blsutil.hpp"
#include "blsprivatekey.hpp"

BLSPrivateKey BLSPrivateKey::FromSeed(const uint8_t* seed, size_t seedLen) {
    BLS::AssertInitialized();

    // "BLS private key seed" in ascii
    const uint8_t hmacKey[] = {66, 76, 83, 32, 112, 114, 105, 118, 97, 116, 101,
                              32, 107, 101, 121, 32, 115, 101, 101, 100};

    uint8_t* hash = BLSUtil::SecAlloc<uint8_t>(
            BLSPrivateKey::PRIVATE_KEY_SIZE);

    // Hash the seed into sk
    relic::md_hmac(hash, seed, seedLen, hmacKey, sizeof(hmacKey));

    relic::bn_t order;
    bn_new(order);
    g1_get_ord(order);

    // Make sure private key is less than the curve order
    relic::bn_t* skBn = BLSUtil::SecAlloc<relic::bn_t>(1);
    bn_new(*skBn);
    bn_read_bin(*skBn, hash, BLSPrivateKey::PRIVATE_KEY_SIZE);
    bn_mod_basic(*skBn, *skBn, order);

    BLSPrivateKey k;
    k.AllocateKeyData();
    bn_copy(*k.keydata, *skBn);

    BLSUtil::SecFree(skBn);
    BLSUtil::SecFree(hash);
    return k;
}

// Construct a private key from a bytearray.
BLSPrivateKey BLSPrivateKey::FromBytes(const uint8_t* bytes, bool modOrder) {
    BLS::AssertInitialized();
    BLSPrivateKey k;
    k.AllocateKeyData();
    bn_read_bin(*k.keydata, bytes, BLSPrivateKey::PRIVATE_KEY_SIZE);
    relic::bn_t ord;
    bn_new(ord);
    g1_get_ord(ord);
    if (modOrder) {
        bn_mod_basic(*k.keydata, *k.keydata, ord);
    } else {
        if (bn_cmp(*k.keydata, ord) > 0) {
            throw std::string("Key data too large, must be smaller than group order");
        }
    }
    return k;
}

// Construct a private key from another private key.
BLSPrivateKey::BLSPrivateKey(const BLSPrivateKey &privateKey) {
    BLS::AssertInitialized();
    AllocateKeyData();
    bn_copy(*keydata, *privateKey.keydata);
}

BLSPrivateKey::BLSPrivateKey(BLSPrivateKey&& k) {
    BLS::AssertInitialized();
    std::swap(keydata, k.keydata);
}

BLSPrivateKey::~BLSPrivateKey() {
    BLS::AssertInitialized();
    BLSUtil::SecFree(keydata);
}

BLSPublicKey BLSPrivateKey::GetPublicKey() const {
    BLS::AssertInitialized();
    relic::g1_t *q = BLSUtil::SecAlloc<relic::g1_t>(1);
    g1_mul_gen(*q, *keydata);

    const BLSPublicKey ret = BLSPublicKey::FromG1(q);
    BLSUtil::SecFree(*q);
    return ret;
}

BLSPrivateKey BLSPrivateKey::AggregateInsecure(std::vector<BLSPrivateKey> const& privateKeys) {
    if (privateKeys.empty()) {
        throw std::string("Number of private keys must be at least 1");
    }

    relic::bn_t order;
    bn_new(order);
    g1_get_ord(order);

    BLSPrivateKey ret(privateKeys[0]);
    for (size_t i = 1; i < privateKeys.size(); i++) {
        relic::bn_add(*ret.keydata, *ret.keydata, *privateKeys[i].keydata);
        relic::bn_mod_basic(*ret.keydata, *ret.keydata, order);
    }
    return ret;
}

BLSPrivateKey BLSPrivateKey::Aggregate(std::vector<BLSPrivateKey> const& privateKeys,
                                       std::vector<BLSPublicKey> const& pubKeys) {
    if (pubKeys.size() != privateKeys.size()) {
        throw std::string("Number of public keys must equal number of private keys");
    }
    if (privateKeys.empty()) {
        throw std::string("Number of keys must be at least 1");
    }

    std::vector<uint8_t*> serPubKeys(pubKeys.size());
    for (size_t i = 0; i < pubKeys.size(); i++) {
        serPubKeys[i] = new uint8_t[BLSPublicKey::PUBLIC_KEY_SIZE];
        pubKeys[i].Serialize(serPubKeys[i]);
    }

    // Sort the public keys and private keys by public key
    std::vector<size_t> keysSorted(privateKeys.size());
    for (size_t i = 0; i < privateKeys.size(); i++) {
        keysSorted[i] = i;
    }

    std::sort(keysSorted.begin(), keysSorted.end(), [&serPubKeys](size_t a, size_t b) {
        return memcmp(serPubKeys[a], serPubKeys[b], BLSPublicKey::PUBLIC_KEY_SIZE) < 0;
    });


    relic::bn_t *computedTs = new relic::bn_t[keysSorted.size()];
    for (size_t i = 0; i < keysSorted.size(); i++) {
        bn_new(computedTs[i]);
    }
    BLS::HashPubKeys(computedTs, keysSorted.size(), serPubKeys, keysSorted);

    // Raise all keys to power of the corresponding t's and aggregate the results into aggKey
    std::vector<BLSPrivateKey> expKeys;
    expKeys.reserve(keysSorted.size());
    for (size_t i = 0; i < keysSorted.size(); i++) {
        auto& k = privateKeys[keysSorted[i]];
        expKeys.emplace_back(k.Mul(computedTs[i]));
    }
    BLSPrivateKey aggKey = BLSPrivateKey::AggregateInsecure(expKeys);

    for (size_t i = 0; i < keysSorted.size(); i++) {
        bn_free(p);
    }
    for (auto p : serPubKeys) {
        delete[] p;
    }
    delete[] computedTs;

    BLS::CheckRelicErrors();
    return aggKey;
}

BLSPrivateKey BLSPrivateKey::Mul(const relic::bn_t n) const {
    relic::bn_t order;
    bn_new(order);
    g2_get_ord(order);

    BLSPrivateKey ret;
    ret.AllocateKeyData();
    bn_mul_comba(*ret.keydata, *keydata, n);
    bn_mod_basic(*ret.keydata, *ret.keydata, order);
    return ret;
}

bool operator==(const BLSPrivateKey& a, const BLSPrivateKey& b) {
    BLS::AssertInitialized();
    return bn_cmp(*a.keydata, *b.keydata) == CMP_EQ;
}

bool operator!=(const BLSPrivateKey& a, const BLSPrivateKey& b) {
    BLS::AssertInitialized();
    return !(a == b);
}

BLSPrivateKey& BLSPrivateKey::operator=(const BLSPrivateKey &rhs) {
    BLS::AssertInitialized();
    BLSUtil::SecFree(keydata);
    AllocateKeyData();
    bn_copy(*keydata, *rhs.keydata);
    return *this;
}

void BLSPrivateKey::Serialize(uint8_t* buffer) const {
    BLS::AssertInitialized();
    bn_write_bin(buffer, BLSPrivateKey::PRIVATE_KEY_SIZE, *keydata);
}

std::vector<uint8_t> BLSPrivateKey::Serialize() const {
    std::vector<uint8_t> data(PRIVATE_KEY_SIZE);
    Serialize(data.data());
    return data;
}

BLSInsecureSignature BLSPrivateKey::SignInsecure(const uint8_t *msg, size_t len) const {
    BLS::AssertInitialized();
    uint8_t messageHash[BLS::MESSAGE_HASH_LEN];
    BLSUtil::Hash256(messageHash, msg, len);
    return SignInsecurePrehashed(messageHash);
}

BLSInsecureSignature BLSPrivateKey::SignInsecurePrehashed(const uint8_t *messageHash) const {
    BLS::AssertInitialized();
    relic::g2_t sig, point;

    g2_map(point, messageHash, BLS::MESSAGE_HASH_LEN, 0);
    g2_mul(sig, point, *keydata);

    return BLSInsecureSignature::FromG2(&sig);
}

BLSSignature BLSPrivateKey::Sign(const uint8_t *msg, size_t len) const {
    BLS::AssertInitialized();
    uint8_t messageHash[BLS::MESSAGE_HASH_LEN];
    BLSUtil::Hash256(messageHash, msg, len);
    return SignPrehashed(messageHash);
}

BLSSignature BLSPrivateKey::SignPrehashed(const uint8_t *messageHash) const {
    BLS::AssertInitialized();

    BLSInsecureSignature insecureSig = SignInsecurePrehashed(messageHash);
    BLSSignature ret = BLSSignature::FromInsecureSig(insecureSig);

    ret.SetAggregationInfo(AggregationInfo::FromMsgHash(GetPublicKey(),
            messageHash));

    return ret;
}

void BLSPrivateKey::AllocateKeyData() {
    BLS::AssertInitialized();
    keydata = BLSUtil::SecAlloc<relic::bn_t>(1);
    bn_new(*keydata);  // Freed in destructor
    relic::bn_zero(*keydata);
}

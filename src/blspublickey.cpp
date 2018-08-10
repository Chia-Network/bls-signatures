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

#include "blspublickey.hpp"
#include "blsutil.hpp"
#include "bls.hpp"

BLSPublicKey BLSPublicKey::FromBytes(const uint8_t * key) {
    BLS::AssertInitialized();
    BLSPublicKey pk = BLSPublicKey();
    std::memcpy(pk.data, key, PUBLIC_KEY_SIZE);
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
    CompressPoint(pk.data, &pk.q);
    return pk;
}

BLSPublicKey::BLSPublicKey(const BLSPublicKey &pubKey) {
    BLS::AssertInitialized();
    relic::g1_t tmp;
    pubKey.GetPoint(tmp);
    g1_copy(q, tmp);
    CompressPoint(data, &q);
}

size_t BLSPublicKey::size() const {
    return PUBLIC_KEY_SIZE;
}

const uint8_t* BLSPublicKey::begin() const {
    return data;
}

const uint8_t* BLSPublicKey::end() const {
    return data + size();
}

const uint8_t& BLSPublicKey::operator[](size_t pos) const {
    return data[pos];
}

void BLSPublicKey::Serialize(uint8_t *buffer) const {
    BLS::AssertInitialized();
    std::memcpy(buffer, data, PUBLIC_KEY_SIZE);
}

// Comparator implementation.
bool operator==(BLSPublicKey const &a,  BLSPublicKey const &b) {
    BLS::AssertInitialized();
    return g1_cmp(a.q, b.q) == CMP_EQ;
}

bool operator!=(BLSPublicKey const&a,  BLSPublicKey const&b) {
    return !(a == b);
}

bool operator<(BLSPublicKey const&a,  BLSPublicKey const&b) {
    return std::memcmp(a.data, b.data, BLSPublicKey::PUBLIC_KEY_SIZE) < 0;
}

std::ostream &operator<<(std::ostream &os, BLSPublicKey const &pk) {
    BLS::AssertInitialized();
    return os << BLSUtil::HexStr(pk.data, BLSPublicKey::PUBLIC_KEY_SIZE);
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

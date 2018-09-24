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
#include "extendedpublickey.hpp"
#include "extendedprivatekey.hpp"
#include "blsutil.hpp"
#include "bls.hpp"

ExtendedPublicKey ExtendedPublicKey::FromBytes(
        const uint8_t* serialized) {
    BLS::AssertInitialized();
    uint32_t version = BLSUtil::FourBytesToInt(serialized);
    uint32_t depth = serialized[4];
    uint32_t parentFingerprint = BLSUtil::FourBytesToInt(serialized + 5);
    uint32_t childNumber = BLSUtil::FourBytesToInt(serialized + 9);
    const uint8_t* ccPointer = serialized + 13;
    const uint8_t* pkPointer = ccPointer + ChainCode::CHAIN_CODE_SIZE;

    ExtendedPublicKey epk(version, depth, parentFingerprint, childNumber,
                          ChainCode::FromBytes(ccPointer),
                          BLSPublicKey::FromBytes(pkPointer));
    return epk;
}

ExtendedPublicKey ExtendedPublicKey::PublicChild(uint32_t i) const {
    BLS::AssertInitialized();
    // Hardened children have i >= 2^31. Non-hardened have i < 2^31
    uint32_t cmp = (1 << 31);
    if (i >= cmp) {
        throw std::string("Cannot derive hardened children from public key");
    }
    if (depth >= 255) {
        throw std::string("Cannot go further than 255 levels");
    }
    uint8_t ILeft[BLSPrivateKey::PRIVATE_KEY_SIZE];
    uint8_t IRight[ChainCode::CHAIN_CODE_SIZE];

    // Chain code is used as hmac key
    uint8_t hmacKey[ChainCode::CHAIN_CODE_SIZE];
    chainCode.Serialize(hmacKey);

    // Public key serialization, i serialization, and one 0 or 1 byte
    size_t inputLen = BLSPublicKey::PUBLIC_KEY_SIZE + 4 + 1;

    // Hmac input includes sk or pk, int i, and byte with 0 or 1
    uint8_t hmacInput[BLSPublicKey::PUBLIC_KEY_SIZE + 4 + 1];

    // Fill the input with the required data
    pk.Serialize(hmacInput);
    hmacInput[inputLen - 1] = 0;
    BLSUtil::IntToFourBytes(hmacInput + BLSPublicKey::PUBLIC_KEY_SIZE, i);

    relic::md_hmac(ILeft, hmacInput, inputLen,
                    hmacKey, ChainCode::CHAIN_CODE_SIZE);

    // Change 1 byte to generate a different sequence for chaincode
    hmacInput[inputLen - 1] = 1;

    relic::md_hmac(IRight, hmacInput, inputLen,
                    hmacKey, ChainCode::CHAIN_CODE_SIZE);

    relic::bn_t leftSk;
    bn_new(leftSk);
    bn_read_bin(leftSk, ILeft, BLSPrivateKey::PRIVATE_KEY_SIZE);

    relic::bn_t order;
    bn_new(order);
    g2_get_ord(order);

    bn_mod_basic(leftSk, leftSk, order);
    relic::g1_t newPk, oldPk;
    g1_mul_gen(newPk, leftSk);
    pk.GetPoint(oldPk);
    g1_add(newPk, newPk, oldPk);

    ExtendedPublicKey epk(version, depth + 1,
                          GetPublicKey().GetFingerprint(), i,
                          ChainCode::FromBytes(IRight),
                          BLSPublicKey::FromG1(&newPk));

    return epk;
}

uint32_t ExtendedPublicKey::GetVersion() const {
    return version;
}

uint8_t ExtendedPublicKey::GetDepth() const {
    return depth;
}

uint32_t ExtendedPublicKey::GetParentFingerprint() const {
    return parentFingerprint;
}

uint32_t ExtendedPublicKey::GetChildNumber() const {
    return childNumber;
}

ChainCode ExtendedPublicKey::GetChainCode() const {
    return chainCode;
}

BLSPublicKey ExtendedPublicKey::GetPublicKey() const {
    return pk;
}

// Comparator implementation.
bool operator==(ExtendedPublicKey const &a,  ExtendedPublicKey const &b) {
    BLS::AssertInitialized();
    return (a.GetPublicKey() == b.GetPublicKey() &&
            a.GetChainCode() == b.GetChainCode());
}

bool operator!=(ExtendedPublicKey const&a,  ExtendedPublicKey const&b) {
    return !(a == b);
}

std::ostream &operator<<(std::ostream &os, ExtendedPublicKey const &a) {
    BLS::AssertInitialized();
    return os << a.GetPublicKey() << a.GetChainCode();
}

void ExtendedPublicKey::Serialize(uint8_t *buffer) const {
    BLS::AssertInitialized();
    BLSUtil::IntToFourBytes(buffer, version);
    buffer[4] = depth;
    BLSUtil::IntToFourBytes(buffer + 5, parentFingerprint);
    BLSUtil::IntToFourBytes(buffer + 9, childNumber);
    chainCode.Serialize(buffer + 13);
    pk.Serialize(buffer + 13 + ChainCode::CHAIN_CODE_SIZE);
}

std::vector<uint8_t> ExtendedPublicKey::Serialize() const {
    std::vector<uint8_t> data(EXTENDED_PUBLIC_KEY_SIZE);
    Serialize(data.data());
    return data;
}
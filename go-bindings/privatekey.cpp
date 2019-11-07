// Copyright 2019 Chia Network Inc

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "privatekey.h"
#include <vector>
#include "bls.hpp"
#include "blschia.h"
#include "error.h"

CPrivateKey CPrivateKeyFromSeed(void *p, int size) {
    bls::PrivateKey* skPtr = new bls::PrivateKey(
        bls::PrivateKey::FromSeed(static_cast<uint8_t *>(p), size)
    );
    return skPtr;
}

CPrivateKey CPrivateKeyFromBytes(void *p, bool modOrder, bool *didErr) {
    bls::PrivateKey* skPtr;
    try {
        skPtr = new bls::PrivateKey(
            bls::PrivateKey::FromBytes(static_cast<uint8_t*>(p), modOrder)
        );
    } catch (const std::exception& ex) {
        // set err
        gErrMsg = ex.what();
        *didErr = true;
        return nullptr;
    }

    return skPtr;
}

void* CPrivateKeySerialize(CPrivateKey inPtr) {
    bls::PrivateKey* key = (bls::PrivateKey*)inPtr;

    uint8_t* buffer = bls::Util::SecAlloc<uint8_t>(
        bls::PrivateKey::PRIVATE_KEY_SIZE);

    key->Serialize(buffer);
    return static_cast<void*>(buffer);
}

void CPrivateKeyFree(CPrivateKey inPtr) {
    bls::PrivateKey* key = (bls::PrivateKey*)inPtr;
    delete key;
}

int CPrivateKeySizeBytes() {
    return bls::PrivateKey::PRIVATE_KEY_SIZE;
}

CPublicKey CPrivateKeyGetPublicKey(CPrivateKey inPtr) {
    bls::PrivateKey* key = (bls::PrivateKey*)inPtr;

    bls::PublicKey* pkPtr = new bls::PublicKey(key->GetPublicKey());

    return pkPtr;
}

// Hash and Sign a message
CInsecureSignature CPrivateKeySignInsecure(CPrivateKey inPtr, void *msg,
    size_t len) {
    bls::PrivateKey* key = (bls::PrivateKey*)inPtr;
    bls::InsecureSignature* sig = new bls::InsecureSignature(
        key->SignInsecure(static_cast<uint8_t*>(msg), len)
    );
    return sig;
}

// Sign a fixed-length hash of a message
CInsecureSignature CPrivateKeySignInsecurePrehashed(CPrivateKey inPtr,
    void *hash) {
    bls::PrivateKey* key = (bls::PrivateKey*)inPtr;
    bls::InsecureSignature* sig = new bls::InsecureSignature(
        key->SignInsecurePrehashed(static_cast<uint8_t*>(hash))
    );
    return sig;
}

// Hash and Sign a message
CSignature CPrivateKeySign(CPrivateKey inPtr, void *msg, size_t len) {
    bls::PrivateKey* key = (bls::PrivateKey*)inPtr;
    bls::Signature* sig = new bls::Signature(
        key->Sign(static_cast<uint8_t*>(msg), len)
    );
    return sig;
}

// Sign a fixed-length hash of a message
CSignature CPrivateKeySignPrehashed(CPrivateKey inPtr, void *hash) {
    bls::PrivateKey* key = (bls::PrivateKey*)inPtr;
    bls::Signature* sig = new bls::Signature(
        key->SignPrehashed(static_cast<uint8_t*>(hash))
    );
    return sig;
}

CPrivateKey CPrivateKeyAggregateInsecure(void **privateKeys,
    size_t numPrivateKeys, bool *didErr) {
    // build privkey vector
    std::vector<bls::PrivateKey> vecPrivKeys;
    for (int i = 0 ; i < numPrivateKeys; ++i) {
        bls::PrivateKey* key = (bls::PrivateKey*)privateKeys[i];
        vecPrivKeys.push_back(*key);
    }

    bls::PrivateKey* key;
    try {
        key = new bls::PrivateKey(
            bls::PrivateKey::AggregateInsecure(vecPrivKeys)
        );
    } catch (const std::exception& ex) {
        // set err
        gErrMsg = ex.what();
        *didErr = true;
        return nullptr;
    }

    return key;
}

CPrivateKey CPrivateKeyAggregate(void **privateKeys, size_t numPrivateKeys,
    void **publicKeys, size_t numPublicKeys, bool *didErr) {
    // build privkey vector
    std::vector<bls::PrivateKey> vecPrivKeys;
    for (int i = 0 ; i < numPrivateKeys; ++i) {
        bls::PrivateKey* key = (bls::PrivateKey*)privateKeys[i];
        vecPrivKeys.push_back(*key);
    }

    // build pubkey vector
    std::vector<bls::PublicKey> vecPubKeys;
    for (int i = 0 ; i < numPublicKeys; ++i) {
        bls::PublicKey* key = (bls::PublicKey*)publicKeys[i];
        vecPubKeys.push_back(*key);
    }

    bls::PrivateKey* key;
    try {
        key = new bls::PrivateKey(
            bls::PrivateKey::Aggregate(vecPrivKeys, vecPubKeys)
        );
    } catch (const std::exception& ex) {
        // set err
        gErrMsg = ex.what();
        *didErr = true;
        return nullptr;
    }

    return key;
}

bool CPrivateKeyIsEqual(CPrivateKey aPtr, CPrivateKey bPtr) {
    bls::PrivateKey* a = (bls::PrivateKey*)aPtr;
    bls::PrivateKey* b = (bls::PrivateKey*)bPtr;

    return *a == *b;
}

CPrivateKey CPrivateKeyFromBN(void *bnBytesPtr, size_t bnSize) {
    bn_t sk;
    bn_new(sk);

    bn_read_bin(sk, static_cast<uint8_t*>(bnBytesPtr), bnSize);

    bls::PrivateKey *key = new bls::PrivateKey(bls::PrivateKey::FromBN(sk));
    return key;
}

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

#include "publickey.h"
#include <vector>
#include <cstring>
#include "bls.hpp"
#include "error.h"

void* CPublicKeySerialize(CPublicKey inPtr) {
    uint8_t* buffer = static_cast<uint8_t*>(
        malloc(bls::PublicKey::PUBLIC_KEY_SIZE));

    bls::PublicKey* key = (bls::PublicKey*)inPtr;
    key->Serialize(buffer);

    return static_cast<void*>(buffer);
}

void CPublicKeyFree(CPublicKey inPtr) {
    bls::PublicKey* key = (bls::PublicKey*)inPtr;
    delete key;
}

int CPublicKeySizeBytes() {
    return bls::PublicKey::PUBLIC_KEY_SIZE;
}

uint32_t CPublicKeyGetFingerprint(CPublicKey inPtr) {
    bls::PublicKey* key = (bls::PublicKey*)inPtr;
    return key->GetFingerprint();
}

CPublicKey CPublicKeyFromBytes(void *p, bool *didErr)  {
    bls::PublicKey* pkPtr;
    try {
        pkPtr = new bls::PublicKey(bls::PublicKey::FromBytes(
            static_cast<uint8_t*>(p)));
    } catch (const std::exception& ex) {
        // set err
        gErrMsg = ex.what();
        *didErr = true;
        return nullptr;
    }
    return pkPtr;
}

CPublicKey CPublicKeyAggregate(void **keys, size_t len, bool *didErr) {
    std::vector<bls::PublicKey> vecKeys;
    for (int i = 0; i < len; i++) {
        bls::PublicKey* key = (bls::PublicKey*)keys[i];
        vecKeys.push_back(*key);
    }

    bls::PublicKey* kPtr;
    try {
        kPtr = new bls::PublicKey(
            bls::PublicKey::Aggregate(vecKeys)
        );
    } catch (const std::exception& ex) {
        // set err
        gErrMsg = ex.what();
        *didErr = true;
        return nullptr;
    }

    return kPtr;
}

CPublicKey CPublicKeyAggregateInsecure(void **keys, size_t len, bool *didErr) {
    std::vector<bls::PublicKey> vecKeys;
    for (int i = 0; i < len; i++) {
        bls::PublicKey* key = (bls::PublicKey*)keys[i];
        vecKeys.push_back(*key);
    }

    bls::PublicKey* kPtr;
    try {
        kPtr = new bls::PublicKey(
            bls::PublicKey::AggregateInsecure(vecKeys)
        );
    } catch (const std::exception& ex) {
        // set err
        gErrMsg = ex.what();
        *didErr = true;
        return nullptr;
    }

    return kPtr;
}

bool CPublicKeyIsEqual(CPublicKey aPtr, CPublicKey bPtr) {
    bls::PublicKey* a = (bls::PublicKey*)aPtr;
    bls::PublicKey* b = (bls::PublicKey*)bPtr;

    return *a == *b;
}

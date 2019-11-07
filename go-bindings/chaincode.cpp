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

#include "bls.hpp"
#include "chaincode.h"

CChainCode CChainCodeFromBytes(void *p) {
    bls::ChainCode* ccPtr = new bls::ChainCode(
        bls::ChainCode::FromBytes(static_cast<uint8_t*>(p)));
    return ccPtr;
}

void CChainCodeFree(CChainCode inPtr) {
    bls::ChainCode* cc = (bls::ChainCode*)inPtr;
    delete cc;
}

int CChainCodeSizeBytes() {
    return bls::ChainCode::CHAIN_CODE_SIZE;
}

void* CChainCodeSerialize(CChainCode inPtr) {
    bls::ChainCode* cc = (bls::ChainCode*)inPtr;

    uint8_t* buffer = static_cast<uint8_t*>(
        malloc(bls::ChainCode::CHAIN_CODE_SIZE));

    cc->Serialize(buffer);
    return static_cast<void*>(buffer);
}

bool CChainCodeIsEqual(CChainCode aPtr, CChainCode bPtr) {
    bls::ChainCode* a = (bls::ChainCode*)aPtr;
    bls::ChainCode* b = (bls::ChainCode*)bPtr;

    return *a == *b;
}

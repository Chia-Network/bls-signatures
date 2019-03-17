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

#ifndef BLS_CHAINCODEWRAPPER_H
#define BLS_CHAINCODEWRAPPER_H

#include "../../src/chaincode.hpp"
#include "emscripten/val.h"
#include "../helpers.h"

using namespace bls;

namespace js_wrappers {
    class ChainCodeWrapper : public JSWrapper<ChainCode> {
    public:
        static const size_t CHAIN_CODE_SIZE;

        explicit ChainCodeWrapper(ChainCode &chainCode);

        static ChainCodeWrapper FromBytes(val jsBuffer);

        val Serialize() const;
    };
}


#endif //BLS_CHAINCODEWRAPPER_H

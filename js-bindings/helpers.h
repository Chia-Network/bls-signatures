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

#ifndef BLS_HELPERS_H
#define BLS_HELPERS_H

#include "relic_conf.h"
#include "relic.h"
#include "relic_bn.h"
#include "emscripten/val.h"
#include <algorithm>
#include "../src/bls.hpp"
#include "wrappers/JSWrapper.h"

using namespace bls;
using namespace emscripten;

namespace helpers {
    val toJSBuffer(uint8_t *pointer, size_t data_size);

    val toJSBuffer(std::vector<uint8_t> vec);

    val toJSBuffer(bn_t bn);

    std::vector<uint8_t> toVector(uint8_t *pointer, size_t data_size);

    std::vector<uint8_t> toVector(val jsBuffer);

    std::vector<uint8_t> toVector(bn_t bn);


    val toJSArray(std::vector<val> vec);

    template<typename T>
    inline std::vector<T> fromJSArray(val array) {
        auto l = array["length"].as<unsigned>();
        std::vector<T> vec;
        for (unsigned i = 0; i < l; ++i) {
            vec.push_back(array[i].as<T>());
        }
        return vec;
    };

    std::vector<std::vector<uint8_t>> jsBuffersArrayToVector(val buffersArray);

    std::vector<bn_t *> jsBuffersArrayToBnVector(val buffersArray);

    val byteArraysVectorToJsBuffersArray(std::vector<uint8_t *> arraysVector, size_t element_size);
}

#endif //BLS_HELPERS_H

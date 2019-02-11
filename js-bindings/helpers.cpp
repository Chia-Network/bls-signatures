//
// Created by anton on 11.02.19.
//

#include <vector>
#include "stdint.h"
#include <stdio.h>
#include "emscripten/val.h"

using namespace emscripten;

namespace helpers {
    /**
     * Converts js Buffer/Uint8Array to vector<uint_8t>
     * @param {emscripten::val} jsUint8Array
     * @return {std::vector<uint8_t>}
     */
    std::vector<uint8_t> uint8ArrayToVector(val jsUint8Array) {
        auto l = jsUint8Array["length"].as<unsigned>();
        std::vector<uint8_t> vec;
        for(unsigned i = 0; i < l; ++i) {
            vec.push_back(jsUint8Array[i].as<uint8_t>());
        }
        return vec;
    }

    val vectorToUint8Array(std::vector<uint8_t> vec) {
        return val(typed_memory_view(vec.size(), vec.data()));
    }
}

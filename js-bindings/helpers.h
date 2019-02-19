//
// Created by anton on 12.02.19.
//

#ifndef BLS_HELPERS_H
#define BLS_HELPERS_H

#include "relic_conf.h"
#include "relic.h"
#include "relic_bn.h"
#include "emscripten/val.h"
#include <algorithm>
#include "../src/bls.hpp"

using namespace bls;
using namespace emscripten;

namespace helpers {
    std::vector<uint8_t> byteArrayToVector(uint8_t* pointer, size_t data_size);
    std::vector<uint8_t> jsBufferToVector(val jsUint8Array);
    std::vector<std::vector<uint8_t>> jsBuffersArrayToVector(val buffersArray);
    std::vector<bn_t*> jsBuffersArrayToBnVector(val buffersArray);
    std::vector<uint8_t> bnToByteVector(bn_t bn);

    val byteArrayToJsBuffer(uint8_t* pointer, size_t data_size);
    val vectorToJSBuffer(std::vector<uint8_t> vec);
    val valVectorToJsArray(std::vector<val> vec);
    val vectorOfVectorsToBuffersArray(std::vector<std::vector<uint8_t>> vec);
    val bnToJsBuffer(bn_t bn);
    val byteArraysVectorToJsBuffersArray(std::vector<uint8_t*> arraysVector, size_t element_size);
}

#endif //BLS_HELPERS_H

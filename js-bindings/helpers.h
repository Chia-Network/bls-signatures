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
    val vectorToJSBuffer(std::vector<uint8_t> vec);
    std::vector<std::vector<uint8_t>> buffersArrayToVector(val arrayOfBuffers);
    val byteArrayToJsBuffer(uint8_t* pointer, size_t data_size);
    val valVectorToJsArray(std::vector<val> vec);
    std::vector<uint8_t> bnToByteVector(bn_t bn);
    val bnToJsBuffer(bn_t bn);
    void jsBufferToBn(bn_t *result, val buffer);
    val byteArraysVectorToJsBuffersArray(std::vector<uint8_t*> arraysVector, size_t element_size);
}

#endif //BLS_HELPERS_H

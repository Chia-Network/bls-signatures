//
// Created by anton on 12.02.19.
//

#ifndef BLS_HELPERS_H
#define BLS_HELPERS_H

#include "emscripten/val.h"

using namespace emscripten;

namespace helpers {
    /**
     * Copies data from a JS Buffer/Uint8Array to vector<uint_8t>
     * @param {emscripten::val} jsUint8Array
     * @return {std::vector<uint8_t>}
     */
    inline std::vector<uint8_t> jsBufferToVector(val jsUint8Array) {
        auto l = jsUint8Array["length"].as<unsigned>();
        std::vector<uint8_t> vec;
        for(unsigned i = 0; i < l; ++i) {
            vec.push_back(jsUint8Array[i].as<uint8_t>());
        }
        return vec;
    }

    /**
     * Copies data from a vector<uint8_t> to a JS Buffer
     * @param {std::vector<uint8_t>} vec
     * @return {emscripten::val}
     */
    inline val vectorToJSBuffer(std::vector<uint8_t> vec) {
        size_t bufferSize = vec.size();
        val Buffer = val::global("Buffer");
        val buffer = Buffer.call<val>("alloc", bufferSize);
        for(unsigned i = 0; i < bufferSize; ++i) {
            buffer.call<void>("writeUInt8", vec[i], i);
        }
        return buffer;
    }

    inline std::vector<std::vector<uint8_t>> buffersArrayToVector(val arrayOfBuffers) {
        auto l = arrayOfBuffers["length"].as<unsigned>();
        std::vector<std::vector<uint8_t>> vec;
        for(unsigned i = 0; i < l; ++i) {
            vec.push_back(jsBufferToVector(arrayOfBuffers[i].as<val>()));
        }
        return vec;
    }
}

#endif //BLS_HELPERS_H

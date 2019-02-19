//
// Created by anton on 17.02.19.
//

#include "helpers.h"

namespace helpers {
    /**
     * Copies data from byte array to a vector
     * @param {uint8_t} pointer
     * @param {size_t} data_size
     * @return {std::vector<uint8_t>}
     */
    std::vector<uint8_t> byteArrayToVector(uint8_t *pointer, size_t data_size) {
        std::vector<uint8_t> data;
        data.reserve(data_size);
        std::copy(pointer, pointer + data_size, std::back_inserter(data));
        return data;
    }

    /**
     * Copies data from a JS Buffer/Uint8Array to vector<uint_8t>
     * @param {emscripten::val} jsUint8Array
     * @return {std::vector<uint8_t>}
     */
    std::vector<uint8_t> jsBufferToVector(val jsUint8Array) {
        auto l = jsUint8Array["length"].as<unsigned>();
        std::vector<uint8_t> vec;
        for (unsigned i = 0; i < l; ++i) {
            vec.push_back(jsUint8Array[i].as<uint8_t>());
        }
        return vec;
    }

    /**
     * Copies data from a vector<uint8_t> to a JS Buffer
     * @param {std::vector<uint8_t>} vec
     * @return {emscripten::val}
     */
    val vectorToJSBuffer(std::vector<uint8_t> vec) {
        size_t bufferSize = vec.size();
        val Buffer = val::global("Buffer");
        val buffer = Buffer.call<val>("alloc", bufferSize);
        for (unsigned i = 0; i < bufferSize; ++i) {
            buffer.call<void>("writeUInt8", vec[i], i);
        }
        return buffer;
    }

    std::vector<std::vector<uint8_t>> jsBuffersArrayToVector(val buffersArray) {
        auto l = buffersArray["length"].as<unsigned>();
        std::vector<std::vector<uint8_t>> vec;
        for (unsigned i = 0; i < l; ++i) {
            vec.push_back(jsBufferToVector(buffersArray[i].as<val>()));
        }
        return vec;
    }

    val vectorOfVectorsToBuffersArray(std::vector<std::vector<uint8_t>> vec) {
        val Array = val::global("Array");
        val arr = Array.new_();
        auto l = vec.size();
        for (unsigned i = 0; i < l; ++i) {
            std::vector<uint8_t> innerVec = vec[i];
            val buffer = vectorToJSBuffer(innerVec);
            arr.call<void>("push", buffer);
        }
        return arr;
    }

    val byteArrayToJsBuffer(uint8_t *pointer, size_t data_size) {
        std::vector<uint8_t> vec = byteArrayToVector(pointer, data_size);
        val buffer = vectorToJSBuffer(vec);
        return buffer;
    }

    val valVectorToJsArray(std::vector<val> vec) {
        val Array = val::global("Array");
        val arr = Array.new_();
        auto l = vec.size();
        for (unsigned i = 0; i < l; ++i) {
            arr.call<void>("push", vec[i]);
        }
        return arr;
    }

    // Note: those methods using relic's bn implementation
    std::vector<uint8_t> bnToByteVector(bn_t bn) {
        uint8_t buf[bn_size_bin(bn)];
        bn_write_bin(buf, bn_size_bin(bn), bn);
        std::vector<uint8_t> vec = helpers::byteArrayToVector(buf, bn_size_bin(bn));
        return vec;
    }

    val bnToJsBuffer(bn_t bn) {
        std::vector<uint8_t> vec = bnToByteVector(bn);
        val buffer = vectorToJSBuffer(vec);
        return buffer;
    }

    std::vector<bn_t *> jsBuffersArrayToBnVector(val buffersArray) {
        auto l = buffersArray["length"].as<unsigned>();
        std::vector<bn_t *> vec;
        for (unsigned i = 0; i < l; ++i) {
            bn_t data;
            //new bn_t[1];
            bn_new(data);
            std::vector<uint8_t> bnVec = jsBufferToVector(buffersArray[i]);
            bn_read_bin(data, bnVec.data(), (int) bnVec.size());
            bn_t *point = &data;
            vec.push_back(point);
        }
        return vec;
    }

    val byteArraysVectorToJsBuffersArray(std::vector<uint8_t *> arraysVector, size_t element_size) {
        auto vecSize = arraysVector.size();
        std::vector<val> valVector;
        for (unsigned i = 0; i < vecSize; ++i) {
            valVector.push_back(byteArrayToJsBuffer(arraysVector[i], element_size));
        }
        val arr = valVectorToJsArray(valVector);
        return arr;
    }
}
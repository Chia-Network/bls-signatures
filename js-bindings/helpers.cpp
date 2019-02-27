//
// Created by anton on 17.02.19.
//

#include "helpers.h"

namespace helpers {
    val toJSBuffer(std::vector<uint8_t> vec) {
        size_t bufferSize = vec.size();
        val Buffer = val::global("Buffer");
        val buffer = Buffer.call<val>("alloc", bufferSize);
        for (unsigned i = 0; i < bufferSize; ++i) {
            buffer.call<void>("writeUInt8", vec[i], i);
        }
        return buffer;
    }

    val toJSBuffer(uint8_t *pointer, size_t data_size) {
        std::vector<uint8_t> vec = toVector(pointer, data_size);
        val buffer = toJSBuffer(vec);
        return buffer;
    }

    val toJSBuffer(bn_t bn) {
        std::vector<uint8_t> vec = toVector(bn);
        val buffer = toJSBuffer(vec);
        return buffer;
    }

    std::vector<uint8_t> toVector(uint8_t *pointer, size_t data_size) {
        std::vector<uint8_t> data;
        data.reserve(data_size);
        std::copy(pointer, pointer + data_size, std::back_inserter(data));
        return data;
    }

    std::vector<uint8_t> toVector(val jsUint8Array) {
        auto l = jsUint8Array["length"].as<unsigned>();
        std::vector<uint8_t> vec;
        for (unsigned i = 0; i < l; ++i) {
            vec.push_back(jsUint8Array[i].as<uint8_t>());
        }
        return vec;
    }

    std::vector<uint8_t> toVector(bn_t bn) {
        uint8_t buf[bn_size_bin(bn)];
        bn_write_bin(buf, bn_size_bin(bn), bn);
        std::vector<uint8_t> vec = helpers::toVector(buf, bn_size_bin(bn));
        return vec;
    }

    val toJSArray(std::vector<val> vec) {
        val Array = val::global("Array");
        val arr = Array.new_();
        auto l = vec.size();
        for (unsigned i = 0; i < l; ++i) {
            arr.call<void>("push", vec[i]);
        }
        return arr;
    }

    /* ====== */

    std::vector<std::vector<uint8_t>> jsBuffersArrayToVector(val buffersArray) {
        auto l = buffersArray["length"].as<unsigned>();
        std::vector<std::vector<uint8_t>> vec;
        for (unsigned i = 0; i < l; ++i) {
            vec.push_back(toVector(buffersArray[i].as<val>()));
        }
        return vec;
    }

    std::vector<bn_t *> jsBuffersArrayToBnVector(val buffersArray) {
        auto l = buffersArray["length"].as<unsigned>();
        std::vector<bn_t *> vec;
        for (unsigned i = 0; i < l; ++i) {
            bn_t data;
            //new bn_t[1];
            bn_new(data);
            std::vector<uint8_t> bnVec = toVector(buffersArray[i]);
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
            valVector.push_back(toJSBuffer(arraysVector[i], element_size));
        }
        val arr = toJSArray(valVector);
        return arr;
    }
}
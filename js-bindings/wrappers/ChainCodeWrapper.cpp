//
// Created by anton on 22.02.19.
//

#include "ChainCodeWrapper.h"

namespace js_wrappers {
    ChainCodeWrapper::ChainCodeWrapper(ChainCode &chainCode) : JSWrapper(chainCode) {};

    ChainCodeWrapper ChainCodeWrapper::FromBytes(val jsBuffer) {
        std::vector<uint8_t> bytes = helpers::toVector(jsBuffer);
        ChainCode chainCode = ChainCode::FromBytes(bytes.data());
    };

    val ChainCodeWrapper::Serialize() const {
        return helpers::toJSBuffer(wrapped.Serialize());
    };
}
//
// Created by anton on 22.02.19.
//

#ifndef BLS_CHAINCODEWRAPPER_H
#define BLS_CHAINCODEWRAPPER_H

#include "../../src/chaincode.hpp"
#include "emscripten/val.h"
#include "../helpers.h"

using namespace bls;

namespace js_wrappers {
    class ChainCodeWrapper {
    public:
        explicit ChainCodeWrapper(ChainCode &chainCode);
        static ChainCodeWrapper FromBytes(val jsBuffer);
        val Serialize() const;

    private:
        ChainCode wrappedChainCode;
    };
}


#endif //BLS_CHAINCODEWRAPPER_H

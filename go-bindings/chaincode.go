package blschia

// #cgo LDFLAGS: -L../build -lbls -lstdc++
// #cgo CXXFLAGS: -std=c++14 -I../src -I../build/contrib/relic/include -I../contrib/relic/include
// #include <stdbool.h>
// #include <stdlib.h>
// #include "chaincode.h"
import "C"
import "runtime"

// ChainCode is used in extended keys to derive child keys
type ChainCode struct {
	cc C.CChainCode
}

// ChainCodeFromBytes creates an ChainCode object given a byte slice
func ChainCodeFromBytes(data []byte) ChainCode {
	// Get a C pointer to bytes
	cBytesPtr := C.CBytes(data)
	defer C.free(cBytesPtr)

	var cc ChainCode
	cc.cc = C.CChainCodeFromBytes(cBytesPtr)
	runtime.SetFinalizer(&cc, func(p *ChainCode) { p.Free() })

	return cc
}

// Serialize returns the serialized byte representation of the ChainCode object
func (cc ChainCode) Serialize() []byte {
	ptr := C.CChainCodeSerialize(cc.cc)
	defer C.free(ptr)
	return C.GoBytes(ptr, C.CChainCodeSizeBytes())
}

// Free releases memory allocated by the ChainCode object
func (cc ChainCode) Free() {
	C.CChainCodeFree(cc.cc)
}

// Equal tests if one ChainCode object is equal to another
func (cc ChainCode) Equal(other ChainCode) bool {
	return bool(C.CChainCodeIsEqual(cc.cc, other.cc))
}

package blschia

// #cgo LDFLAGS: -L../build -lbls -lstdc++
// #cgo CXXFLAGS: -std=c++14 -I../src -I../build/contrib/relic/include -I../contrib/relic/include
// #include <stdbool.h>
// #include <stdlib.h>
// #include "blschia.h"
import "C"
import (
	"errors"
	"math/big"
	"runtime"
	"unsafe"
)

// AggregationInfo represents information about how aggregation was performed,
// or how a signature was generated (pks, messageHashes, etc).
type AggregationInfo struct {
	ai C.CAggregationInfo
}

// AggregationInfoFromMsg creates an AggregationInfo object given a PublicKey
// and a message payload.
func AggregationInfoFromMsg(pk PublicKey, message []byte) AggregationInfo {
	// Get a C pointer to bytes
	cMessagePtr := C.CBytes(message)
	defer C.free(cMessagePtr)

	var ai AggregationInfo
	ai.ai = C.CAggregationInfoFromMsg(pk.pk, cMessagePtr, C.size_t(len(message)))
	runtime.SetFinalizer(&ai, func(p *AggregationInfo) { p.Free() })
	return ai
}

// AggregationInfoFromMsgHash creates an AggregationInfo object given a
// PublicKey and a pre-hashed message payload.
func AggregationInfoFromMsgHash(pk PublicKey, hash []byte) AggregationInfo {
	// Get a C pointer to bytes
	cMessagePtr := C.CBytes(hash)
	defer C.free(cMessagePtr)

	var ai AggregationInfo
	ai.ai = C.CAggregationInfoFromMsgHash(pk.pk, cMessagePtr)
	runtime.SetFinalizer(&ai, func(p *AggregationInfo) { p.Free() })
	return ai
}

// AggregationInfoFromSlices creates an AggregationInfo object given a list of
// public keys, a list of message hashes and a list of exponents
func AggregationInfoFromSlices(publicKeys []PublicKey, messageHashes [][]byte, exponents []*big.Int) (AggregationInfo, error) {
	// Get a C pointer to an array of public keys
	cNumPublicKeys := C.size_t(len(publicKeys))
	cPublicKeysPtr := C.AllocPtrArray(cNumPublicKeys)
	defer C.FreePtrArray(cPublicKeysPtr)
	// Loop thru each key and add the key C ptr to the array of ptrs at index
	for i, key := range publicKeys {
		C.SetPtrArray(cPublicKeysPtr, unsafe.Pointer(key.pk), C.int(i))
	}

	// Get a C pointer to an array of hashes
	cNumHashes := C.size_t(len(messageHashes))
	cHashArrayPtr := C.AllocPtrArray(cNumHashes)
	defer C.FreePtrArray(cHashArrayPtr)
	// Loop thru each message and add the key C ptr to the array of ptrs at
	// index
	for i, msg := range messageHashes {
		// Get a C pointer to bytes
		cHashPtr := C.CBytes(msg)
		defer C.free(cHashPtr)
		C.SetPtrArray(cHashArrayPtr, cHashPtr, C.int(i))
	}

	// Get a C pointer to pointer to bytes
	cNumExponents := C.size_t(len(exponents))
	cExponentsArrayPtr := C.AllocPtrArray(cNumExponents)
	defer C.FreePtrArray(cExponentsArrayPtr)
	// Get a C size_t pointer for (variable) sizes of exponents
	sizesPtr := C.AllocIntPtr(cNumExponents)
	defer C.FreeIntPtr(sizesPtr)
	// Loop thru each exponent and add the bytes C ptr to the array of ptrs at
	// index
	for i, bn := range exponents {
		// Get a C pointer to bytes
		bnBytes := bn.Bytes()
		C.SetIntPtrVal(sizesPtr, C.size_t(len(bnBytes)), C.int(i))
		cBNBytesPtr := C.CBytes(bnBytes)
		defer C.free(cBNBytesPtr)
		C.SetPtrArray(cExponentsArrayPtr, cBNBytesPtr, C.int(i))
	}

	var ai AggregationInfo
	var cDidErr C.bool
	ai.ai = C.CAggregationInfoFromVectors(cPublicKeysPtr, cNumPublicKeys,
		cHashArrayPtr, cNumHashes, cExponentsArrayPtr, cNumExponents, sizesPtr,
		&cDidErr)
	if bool(cDidErr) {
		cErrMsg := C.GetLastErrorMsg()
		err := errors.New(C.GoString(cErrMsg))
		return AggregationInfo{}, err
	}

	runtime.SetFinalizer(&ai, func(p *AggregationInfo) { p.Free() })
	return ai, nil
}

// Free releases memory allocated by the AggregationInfo object
func (ai AggregationInfo) Free() {
	C.CAggregationInfoFree(ai.ai)
}

// MergeAggregationInfos merges multiple AggregationInfo objects into one.
func MergeAggregationInfos(AIs []AggregationInfo) AggregationInfo {
	// Get a C pointer to an array of aggregation info objects
	cAIsPtr := C.AllocPtrArray(C.size_t(len(AIs)))
	defer C.FreePtrArray(cAIsPtr)

	// Loop thru each AggInfo and add the key C ptr to the array of ptrs at index
	for i, aggInfo := range AIs {
		C.SetPtrArray(cAIsPtr, unsafe.Pointer(aggInfo.ai), C.int(i))
	}

	var ai AggregationInfo
	ai.ai = C.MergeAggregationInfos(cAIsPtr, C.size_t(len(AIs)))
	runtime.SetFinalizer(&ai, func(p *AggregationInfo) { p.Free() })

	return ai
}

// RemoveEntries removes the messages and pubkeys from the tree
func (ai *AggregationInfo) RemoveEntries(messages [][]byte, publicKeys []PublicKey) error {
	// Get a C pointer to an array of messages
	cNumMessages := C.size_t(len(messages))
	cMessageArrayPtr := C.AllocPtrArray(cNumMessages)
	defer C.FreePtrArray(cMessageArrayPtr)

	// Loop thru each message and add the key C ptr to the array of ptrs at
	// index
	for i, msg := range messages {
		// Get a C pointer to bytes
		cMessagePtr := C.CBytes(msg)
		defer C.free(cMessagePtr)
		C.SetPtrArray(cMessageArrayPtr, cMessagePtr, C.int(i))
	}

	// Get a C pointer to an array of public keys
	cNumPublicKeys := C.size_t(len(publicKeys))
	cPublicKeysPtr := C.AllocPtrArray(cNumPublicKeys)
	defer C.FreePtrArray(cPublicKeysPtr)
	// Loop thru each key and add the key C ptr to the array of ptrs at index
	for i, key := range publicKeys {
		C.SetPtrArray(cPublicKeysPtr, unsafe.Pointer(key.pk), C.int(i))
	}

	var cDidErr C.bool
	C.CAggregationInfoRemoveEntries(ai.ai, cMessageArrayPtr, cNumMessages,
		cPublicKeysPtr, cNumPublicKeys, &cDidErr)
	if bool(cDidErr) {
		cErrMsg := C.GetLastErrorMsg()
		err := errors.New(C.GoString(cErrMsg))
		return err
	}

	return nil
}

// Equal tests if two AggregationInfo objects are equal
func (ai AggregationInfo) Equal(other AggregationInfo) bool {
	return bool(C.CAggregationInfoIsEqual(ai.ai, other.ai))
}

// Less tests if one AggregationInfo object is less than the other
func (ai AggregationInfo) Less(other AggregationInfo) bool {
	return bool(C.CAggregationInfoIsLess(ai.ai, other.ai))
}

// Empty tests whether an AggregationInfo object is empty
func (ai AggregationInfo) Empty() bool {
	return bool(C.CAggregationInfoEmpty(ai.ai))
}

// GetPubKeys returns the PublicKeys referenced by the AggregationInfo object
func (ai AggregationInfo) GetPubKeys() []PublicKey {
	// Get a C pointer to an array of bytes
	var cNumKeys C.size_t
	cPubKeysPtr := C.CAggregationInfoGetPubKeys(ai.ai, &cNumKeys)
	defer C.free(unsafe.Pointer(cPubKeysPtr))

	numKeys := int(cNumKeys)
	keys := make([]PublicKey, numKeys)
	for i := 0; i < numKeys; i++ {
		keyPtr := C.GetAddressAtIndex(cPubKeysPtr, C.int(i))
		pkBytes := C.GoBytes(unsafe.Pointer(keyPtr), C.CPublicKeySizeBytes())
		keys[i], _ = PublicKeyFromBytes(pkBytes)
	}

	return keys
}

// GetMessageHashes returns the message hashes referenced by the
// AggregationInfo object
func (ai AggregationInfo) GetMessageHashes() [][]byte {
	// Get a C pointer to an array of message hashes
	var cNumHashes C.size_t
	hashPtr := C.CAggregationInfoGetMessageHashes(ai.ai, &cNumHashes)
	defer C.free(unsafe.Pointer(hashPtr))

	numHashes := int(cNumHashes)
	hashes := make([][]byte, numHashes)
	for i := 0; i < numHashes; i++ {
		// get the singular pointer at index
		hashPtr := C.GetAddressAtIndex(hashPtr, C.int(i))
		hashes[i] = C.GoBytes(hashPtr, C.CBLSMessageHashLen())
	}

	return hashes
}

// GetExponents returns the exponents from the AggregationInfo object
func (ai AggregationInfo) GetExponents() []*big.Int {
	cNumExponents := C.CAggregationInfoGetLength(ai.ai)
	numExponents := int(cNumExponents)

	// Get a C size_t pointer for (variable) sizes of exponents
	sizesPtr := C.AllocIntPtr(cNumExponents)
	defer C.FreeIntPtr(sizesPtr)

	// Get a C pointer to an array of exponents
	cExpPtr := C.CAggregationInfoGetExponents(ai.ai, sizesPtr)
	defer C.FreePtrArray(cExpPtr)

	exponents := make([]*big.Int, numExponents)
	for i := 0; i < numExponents; i++ {
		ptr := C.GetPtrAtIndex(cExpPtr, C.int(i))
		cSizePtr := C.GetIntPtrVal(sizesPtr, C.int(i))
		expBytes := C.GoBytes(ptr, C.int(cSizePtr))
		exponents[i] = new(big.Int).SetBytes(expBytes)
	}

	return exponents
}

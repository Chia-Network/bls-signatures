package blschia

// #cgo LDFLAGS: -L../build -lbls -lstdc++
// #cgo CXXFLAGS: -std=c++14 -I../src -I../build/contrib/relic/include -I../contrib/relic/include
// #include <stdbool.h>
// #include <stdlib.h>
// #include "signature.h"
// #include "blschia.h"
import "C"
import (
	"errors"
	"runtime"
	"unsafe"
)

// InsecureSignature represents an insecure BLS signature.
type InsecureSignature struct {
	sig C.CInsecureSignature
}

// Signature represents a BLS signature with aggregation info.
type Signature struct {
	sig C.CSignature
}

// InsecureSignatureFromBytes constructs a new insecure signature from bytes
func InsecureSignatureFromBytes(data []byte) (InsecureSignature, error) {
	// Get a C pointer to bytes
	cBytesPtr := C.CBytes(data)
	defer C.free(cBytesPtr)

	var sig InsecureSignature
	var cDidErr C.bool
	sig.sig = C.CInsecureSignatureFromBytes(cBytesPtr, &cDidErr)
	if bool(cDidErr) {
		cErrMsg := C.GetLastErrorMsg()
		err := errors.New(C.GoString(cErrMsg))
		return InsecureSignature{}, err
	}

	runtime.SetFinalizer(&sig, func(p *InsecureSignature) { p.Free() })
	return sig, nil
}

// Serialize returns the byte representation of the signature
func (sig InsecureSignature) Serialize() []byte {
	ptr := C.CInsecureSignatureSerialize(sig.sig)
	defer C.free(ptr)
	return C.GoBytes(ptr, C.CInsecureSignatureSizeBytes())
}

// Free releases memory allocated by the signature
func (sig InsecureSignature) Free() {
	C.CInsecureSignatureFree(sig.sig)
}

// SignatureFromBytes creates a new Signature object from the raw bytes
func SignatureFromBytes(data []byte) (Signature, error) {
	// Get a C pointer to bytes
	cBytesPtr := C.CBytes(data)
	defer C.free(cBytesPtr)

	var sig Signature
	var cDidErr C.bool
	sig.sig = C.CSignatureFromBytes(cBytesPtr, &cDidErr)
	if bool(cDidErr) {
		cErrMsg := C.GetLastErrorMsg()
		err := errors.New(C.GoString(cErrMsg))
		return Signature{}, err
	}

	runtime.SetFinalizer(&sig, func(p *Signature) { p.Free() })
	return sig, nil
}

// Serialize returns the byte representation of the signature
func (sig Signature) Serialize() []byte {
	ptr := C.CSignatureSerialize(sig.sig)
	defer C.free(ptr)
	return C.GoBytes(ptr, C.CSignatureSizeBytes())
}

// Free releases memory allocated by the signature
func (sig Signature) Free() {
	C.CSignatureFree(sig.sig)
}

// Verify a single or aggregate signature
func (sig Signature) Verify() bool {
	return bool(C.CSignatureVerify(sig.sig))
}

// SetAggregationInfo sets the aggregation information on this signature, which
// describes how this signature was generated, and how it should be verified.
func (sig Signature) SetAggregationInfo(ai AggregationInfo) {
	C.CSignatureSetAggregationInfo(sig.sig, ai.ai)
}

// GetAggregationInfo returns the aggregation info on this signature.
func (sig Signature) GetAggregationInfo() AggregationInfo {
	var ai AggregationInfo
	ai.ai = C.CSignatureGetAggregationInfo(sig.sig)
	// nothing is newly allocated here, so no need to set a finalizer
	return ai
}

// SignatureAggregate aggregates many signatures using the secure aggregation
// method.
func SignatureAggregate(signatures []Signature) (Signature, error) {
	// Get a C pointer to an array of signatures
	cSigArrPtr := C.AllocPtrArray(C.size_t(len(signatures)))
	defer C.FreePtrArray(cSigArrPtr)

	// Loop thru each sig and add the pointer to it, to the C pointer array at
	// the given index.
	for i, sig := range signatures {
		C.SetPtrArray(cSigArrPtr, unsafe.Pointer(sig.sig), C.int(i))
	}

	var sig Signature
	var cDidErr C.bool
	sig.sig = C.CSignatureAggregate(cSigArrPtr, C.size_t(len(signatures)), &cDidErr)
	if bool(cDidErr) {
		cErrMsg := C.GetLastErrorMsg()
		err := errors.New(C.GoString(cErrMsg))
		return Signature{}, err
	}

	runtime.SetFinalizer(&sig, func(p *Signature) { p.Free() })
	return sig, nil
}

// DivideBy divides the aggregate signature (this) by a list of signatures.
//
// These divisors can be single or aggregate signatures, but all msg/pk pairs
// in these signatures must be distinct and unique.
func (sig Signature) DivideBy(signatures []Signature) (Signature, error) {
	if len(signatures) == 0 {
		return sig, nil
	}

	// Get a C pointer to an array of signatures
	cSigArrPtr := C.AllocPtrArray(C.size_t(len(signatures)))
	defer C.FreePtrArray(cSigArrPtr)
	// Loop thru each sig and add the pointer to it, to the C pointer array at
	// the given index.
	for i, sig := range signatures {
		C.SetPtrArray(cSigArrPtr, unsafe.Pointer(sig.sig), C.int(i))
	}

	var quo Signature
	var cDidErr C.bool
	quo.sig = C.CSignatureDivideBy(sig.sig, cSigArrPtr, C.size_t(len(signatures)), &cDidErr)
	if bool(cDidErr) {
		cErrMsg := C.GetLastErrorMsg()
		err := errors.New(C.GoString(cErrMsg))
		return Signature{}, err
	}

	runtime.SetFinalizer(&quo, func(p *Signature) { p.Free() })
	return quo, nil
}

// DivideBy insecurely divides signatures
func (sig InsecureSignature) DivideBy(signatures []InsecureSignature) (InsecureSignature, error) {
	if len(signatures) == 0 {
		return sig, nil
	}

	// Get a C pointer to an array of signatures
	cSigArrPtr := C.AllocPtrArray(C.size_t(len(signatures)))
	defer C.FreePtrArray(cSigArrPtr)
	// Loop thru each sig and add the pointer to it, to the C pointer array at
	// the given index.
	for i, sig := range signatures {
		C.SetPtrArray(cSigArrPtr, unsafe.Pointer(sig.sig), C.int(i))
	}

	var quo InsecureSignature
	var cDidErr C.bool
	quo.sig = C.CInsecureSignatureDivideBy(sig.sig, cSigArrPtr, C.size_t(len(signatures)), &cDidErr)
	if bool(cDidErr) {
		cErrMsg := C.GetLastErrorMsg()
		err := errors.New(C.GoString(cErrMsg))
		return InsecureSignature{}, err
	}

	runtime.SetFinalizer(&quo, func(p *InsecureSignature) { p.Free() })
	return quo, nil
}

// Verify a single or aggregate signature
//
// This verification method is insecure in regard to the rogue public key
// attack
func (sig InsecureSignature) Verify(hashes [][]byte, publicKeys []PublicKey) bool {
	if (len(hashes) != len(publicKeys)) || len(hashes) == 0 {
		// panic("hashes and pubKeys vectors must be of same size and non-empty")
		return false
	}

	// Get a C pointer to an array of message hashes
	cNumHashes := C.size_t(len(hashes))
	cHashesPtr := C.AllocPtrArray(cNumHashes)
	defer C.FreePtrArray(cHashesPtr)
	// Loop thru each message and add the key C ptr to the array of ptrs at index
	for i, hash := range hashes {
		cBytesPtr := C.CBytes(hash)
		defer C.free(cBytesPtr)
		C.SetPtrArray(cHashesPtr, cBytesPtr, C.int(i))
	}

	// Get a C pointer to an array of public keys
	cNumPublicKeys := C.size_t(len(publicKeys))
	cPublicKeysPtr := C.AllocPtrArray(cNumPublicKeys)
	defer C.FreePtrArray(cPublicKeysPtr)
	// Loop thru each key and add the key C ptr to the array of ptrs at index
	for i, key := range publicKeys {
		C.SetPtrArray(cPublicKeysPtr, unsafe.Pointer(key.pk), C.int(i))
	}

	return bool(C.CInsecureSignatureVerify(sig.sig, cHashesPtr, cNumHashes,
		cPublicKeysPtr, cNumPublicKeys))
}

// InsecureSignatureAggregate insecurely aggregates signatures
func InsecureSignatureAggregate(signatures []InsecureSignature) (InsecureSignature, error) {
	// Get a C pointer to an array of signatures
	cSigArrPtr := C.AllocPtrArray(C.size_t(len(signatures)))
	defer C.FreePtrArray(cSigArrPtr)
	// Loop thru each sig and add the pointer to it, to the C pointer array at
	// the given index.
	for i, sig := range signatures {
		C.SetPtrArray(cSigArrPtr, unsafe.Pointer(sig.sig), C.int(i))
	}

	var sig InsecureSignature
	var cDidErr C.bool
	sig.sig = C.CInsecureSignatureAggregate(cSigArrPtr, C.size_t(len(signatures)), &cDidErr)
	if bool(cDidErr) {
		cErrMsg := C.GetLastErrorMsg()
		err := errors.New(C.GoString(cErrMsg))
		return InsecureSignature{}, err
	}

	runtime.SetFinalizer(&sig, func(p *InsecureSignature) { p.Free() })
	return sig, nil
}

// Equal tests if one InsecureSignature object is equal to another
func (sig InsecureSignature) Equal(other InsecureSignature) bool {
	return bool(C.CInsecureSignatureIsEqual(sig.sig, other.sig))
}

// Equal tests if one Signature object is equal to another
func (sig Signature) Equal(other Signature) bool {
	return bool(C.CSignatureIsEqual(sig.sig, other.sig))
}

// SignatureFromBytesWithAggregationInfo creates a new Signature object from
// the raw bytes and aggregation info
func SignatureFromBytesWithAggregationInfo(data []byte, ai AggregationInfo) (Signature, error) {
	// Get a C pointer to bytes
	cBytesPtr := C.CBytes(data)
	defer C.free(cBytesPtr)

	var sig Signature
	var cDidErr C.bool
	sig.sig = C.CSignatureFromBytesWithAggregationInfo(cBytesPtr, ai.ai, &cDidErr)
	if bool(cDidErr) {
		cErrMsg := C.GetLastErrorMsg()
		err := errors.New(C.GoString(cErrMsg))
		return Signature{}, err
	}

	runtime.SetFinalizer(&sig, func(p *Signature) { p.Free() })
	return sig, nil
}

// SignatureFromInsecureSig constructs a signature from an insecure signature
// (but has no aggregation info)
func SignatureFromInsecureSig(isig InsecureSignature) Signature {
	var sig Signature
	sig.sig = C.CSignatureFromInsecureSig(isig.sig)
	runtime.SetFinalizer(&sig, func(p *Signature) { p.Free() })
	return sig
}

// SignatureFromInsecureSigWithAggregationInfo constructs a secure signature
// from an insecure signature and aggregation info
func SignatureFromInsecureSigWithAggregationInfo(isig InsecureSignature, ai AggregationInfo) Signature {
	var sig Signature
	sig.sig = C.CSignatureFromInsecureSigWithAggregationInfo(isig.sig, ai.ai)
	runtime.SetFinalizer(&sig, func(p *Signature) { p.Free() })
	return sig
}

// GetInsecureSig returns an insecure signature from the secure variant
func (sig Signature) GetInsecureSig() InsecureSignature {
	var isig InsecureSignature
	isig.sig = C.CSignatureGetInsecureSig(sig.sig)
	runtime.SetFinalizer(&isig, func(p *InsecureSignature) { p.Free() })
	return isig
}

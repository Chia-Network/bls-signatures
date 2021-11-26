package blschia

// #cgo LDFLAGS: -lstdc++ -lgmp -lbls -lrelic_s -lsodium
// #cgo CXXFLAGS: -std=c++14
// #include <stdbool.h>
// #include <stdlib.h>
// #include "elements.h"
// #include "blschia.h"
import "C"
import (
	"runtime"
	"unsafe"
)

// G1Element represents a bls::G1Element (48 bytes)
// in fact G1Element is corresponding to a public-key
type G1Element struct {
	val C.CG1Element
}

// G1ElementFromBytes returns a new G1Element (public-key) from bytes
func G1ElementFromBytes(data []byte) (*G1Element, error) {
	cBytesPtr := C.CBytes(data)
	defer C.free(cBytesPtr)
	var cDidErr C.bool
	el := G1Element{
		val: C.CG1ElementFromBytes(cBytesPtr, &cDidErr),
	}
	if bool(cDidErr) {
		return nil, errFromC()
	}
	runtime.SetFinalizer(&el, func(el *G1Element) { el.Free() })
	return &el, nil
}

// Mul performs multiplication operation with PrivateKey and returns a new G1Element (public-key)
func (g *G1Element) Mul(sk *PrivateKey) *G1Element {
	el := G1Element{
		val: C.CG1ElementMul(g.val, sk.val),
	}
	runtime.SetFinalizer(&el, func(el *G1Element) { el.Free() })
	return &el
}

// Free releases allocated memory for bls::G1Element
func (g *G1Element) Free() {
	C.CG1ElementFree(g.val)
}

// IsEqual returns true if the elements are equal otherwise returns false
func (g *G1Element) IsEqual(el *G1Element) bool {
	return bool(C.CG1ElementIsEqual(g.val, el.val))
}

// IsValid returns true if a state of G1Element (public key) is valid
func (g *G1Element) IsValid() bool {
	return bool(C.CG1ElementIsValid(g.val))
}

// Add performs addition operation on the passed G1Element (public key) and returns a new G1Element (public key)
func (g *G1Element) Add(el *G1Element) *G1Element {
	res := G1Element{
		val: C.CG1ElementAdd(g.val, el.val),
	}
	runtime.SetFinalizer(&res, func(res *G1Element) { res.Free() })
	return &res
}

// Fingerprint returns a fingerprint of G1Element (public key)
func (g *G1Element) Fingerprint() int {
	return int(C.CG1ElementGetFingerprint(g.val))
}

// Serialize serializes G1Element (public key) into a slice of bytes and returns its
func (g *G1Element) Serialize() []byte {
	ptr := C.CG1ElementSerialize(g.val)
	defer C.free(unsafe.Pointer(ptr))
	return C.GoBytes(ptr, C.CG1ElementSize())
}

// G2Element represents a bls::G2Element (96 bytes)
// in fact G2Element is corresponding to a signature
type G2Element struct {
	val C.CG2Element
}

// G2ElementFromBytes returns a new G2Element (signature) from passed byte slice
func G2ElementFromBytes(data []byte) (*G2Element, error) {
	cBytesPtr := C.CBytes(data)
	defer C.free(cBytesPtr)
	var cDidErr C.bool
	el := G2Element{
		val: C.CG2ElementFromBytes(cBytesPtr, &cDidErr),
	}
	if bool(cDidErr) {
		return nil, errFromC()
	}
	runtime.SetFinalizer(&el, func(el *G2Element) { el.Free() })
	return &el, nil
}

// Free releases an allocated memory for bls::G2Element
func (g *G2Element) Free() {
	C.CG2ElementFree(g.val)
}

// IsEqual returns true if the elements are equal, otherwise returns false
func (g *G2Element) IsEqual(el *G2Element) bool {
	isEqual := bool(C.CG2ElementIsEqual(g.val, el.val))
	return isEqual
}

// Add performs an addition operation on the passed G2Element (signature) and returns a new G2Element (signature)
func (g *G2Element) Add(el *G2Element) *G2Element {
	res := G2Element{
		val: C.CG2ElementAdd(g.val, el.val),
	}
	runtime.SetFinalizer(&res, func(res *G2Element) { res.Free() })
	return &res
}

// Mul performs multiplication operation with PrivateKey and returns a new G2Element (signature)
func (g *G2Element) Mul(sk *PrivateKey) *G2Element {
	el := G2Element{
		val: C.CG2ElementMul(g.val, sk.val),
	}
	runtime.SetFinalizer(&el, func(el *G2Element) { el.Free() })
	return &el
}

// Serialize serializes G2Element (signature) into a slice of bytes and returns its
func (g *G2Element) Serialize() []byte {
	ptr := C.CG2ElementSerialize(g.val)
	defer C.free(unsafe.Pointer(ptr))
	runtime.KeepAlive(g)
	return C.GoBytes(ptr, C.CG2ElementSize())
}

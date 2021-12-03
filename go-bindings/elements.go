// Copyright (c) 2021 The Dash Core developers

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package blschia

// #include <stdbool.h>
// #include <stdlib.h>
// #include "elements.h"
// #include "blschia.h"
import "C"
import (
	"encoding/hex"
	"runtime"
	"unsafe"
)

// G1Element represents a bls::G1Element (48 bytes)
// in fact G1Element is corresponding to a public-key
type G1Element struct {
	val C.CG1Element
}

// G1ElementFromBytes returns a new G1Element (public-key) from bytes
// this method allocates the new bls::G2Element object and keeps its pointer
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
	runtime.SetFinalizer(&el, func(el *G1Element) { el.free() })
	return &el, nil
}

// Mul performs multiplication operation with PrivateKey and returns a new G1Element (public-key)
// this method is the binding of the multiplication operation
func (g *G1Element) Mul(sk *PrivateKey) *G1Element {
	el := G1Element{
		val: C.CG1ElementMul(g.val, sk.val),
	}
	runtime.SetFinalizer(&el, func(el *G1Element) { el.free() })
	return &el
}

// EqualTo returns true if the elements are equal otherwise returns false
// this method is the binding of the equality operation
func (g *G1Element) EqualTo(el *G1Element) bool {
	return bool(C.CG1ElementIsEqual(g.val, el.val))
}

// IsValid returns true if a state of G1Element (public key) is valid
// this method is the binding of the bls::G1Element::IsValid
func (g *G1Element) IsValid() bool {
	return bool(C.CG1ElementIsValid(g.val))
}

// Add performs addition operation on the passed G1Element (public key) and returns a new G1Element (public key)
// this method is a binding of the bls::G1Element::GetFingerprint
func (g *G1Element) Add(el *G1Element) *G1Element {
	res := G1Element{
		val: C.CG1ElementAdd(g.val, el.val),
	}
	runtime.SetFinalizer(&res, func(res *G1Element) { res.free() })
	return &res
}

// Fingerprint returns a fingerprint of G1Element (public key)
// this method is a binding of the bls::G1Element::GetFingerprint
func (g *G1Element) Fingerprint() int {
	return int(C.CG1ElementGetFingerprint(g.val))
}

// Serialize serializes G1Element (public key) into a slice of bytes and returns it
// this method is a binding of the bls::G1Element::Serialize
func (g *G1Element) Serialize() []byte {
	ptr := C.CG1ElementSerialize(g.val)
	defer C.free(unsafe.Pointer(ptr))
	return C.GoBytes(ptr, C.CG1ElementSize())
}

// HexString returns a hex string representation of serialized data
func (g *G1Element) HexString() string {
	return hex.EncodeToString(g.Serialize())
}

// free calls CG1ElementFree "C" function to release a memory allocated for bls::G1Element
func (g *G1Element) free() {
	C.CG1ElementFree(g.val)
}

// G2Element represents a bls::G2Element (96 bytes)
// in fact G2Element is corresponding to a signature
type G2Element struct {
	val C.CG2Element
}

// G2ElementFromBytes returns a new G2Element (signature) from passed byte slice
// this method allocates the new bls::G2Element object and keeps its pointer
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
	runtime.SetFinalizer(&el, func(el *G2Element) { el.free() })
	return &el, nil
}

// EqualTo returns true if the elements are equal, otherwise returns false
// this method is the binding of the equality operation
func (g *G2Element) EqualTo(el *G2Element) bool {
	isEqual := bool(C.CG2ElementIsEqual(g.val, el.val))
	return isEqual
}

// Add performs an addition operation on the passed G2Element (signature) and returns a new G2Element (signature)
// this method is the binding of the addition operation
func (g *G2Element) Add(el *G2Element) *G2Element {
	res := G2Element{
		val: C.CG2ElementAdd(g.val, el.val),
	}
	runtime.SetFinalizer(&res, func(res *G2Element) { res.free() })
	return &res
}

// Mul performs multiplication operation with PrivateKey and returns a new G2Element (signature)
// this method is the binding of the multiplication operation
func (g *G2Element) Mul(sk *PrivateKey) *G2Element {
	el := G2Element{
		val: C.CG2ElementMul(g.val, sk.val),
	}
	runtime.SetFinalizer(&el, func(el *G2Element) { el.free() })
	return &el
}

// Serialize serializes G2Element (signature) into a slice of bytes and returns it
// this method is a binding of the bls::G2Element::Serialize
func (g *G2Element) Serialize() []byte {
	ptr := C.CG2ElementSerialize(g.val)
	defer C.free(unsafe.Pointer(ptr))
	return C.GoBytes(ptr, C.CG2ElementSize())
}

// HexString returns a hex string representation of serialized data
func (g *G2Element) HexString() string {
	return hex.EncodeToString(g.Serialize())
}

// free calls CG2ElementFree "C" function to release a memory allocated for bls::G2Element
func (g *G2Element) free() {
	C.CG2ElementFree(g.val)
}

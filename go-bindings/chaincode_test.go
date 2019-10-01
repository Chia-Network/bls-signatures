package blschia_test

import (
	"bytes"
	"testing"

	bls "github.com/nmarley/bls-signatures/go-bindings"
)

func TestChainCode(t *testing.T) {
	cc1 := bls.ChainCodeFromBytes(sk1Bytes)
	cc1Bytes := cc1.Serialize()
	if !bytes.Equal(cc1Bytes, sk1Bytes) {
		t.Errorf("got %v, expected %v", cc1Bytes, sk1Bytes)
	}

	cc2 := bls.ChainCodeFromBytes(sk2Bytes)
	if cc1.Equal(cc2) {
		t.Error("cc1 should NOT be equal to cc2")
	}

	cc3 := bls.ChainCodeFromBytes(cc1Bytes)
	if !cc1.Equal(cc3) {
		t.Error("cc1 should be equal to cc3")
	}

	cc1.Free()
	cc2.Free()
	cc3.Free()
}

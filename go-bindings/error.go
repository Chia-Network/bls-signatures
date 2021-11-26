package blschia

// #cgo LDFLAGS: -lbls
// #include "blschia.h"
import "C"
import "errors"

func errFromC() error {
	return errors.New(C.GoString(C.GetLastErrorMsg()))
}

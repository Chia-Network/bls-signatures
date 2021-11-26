package blschia

// #cgo LDFLAGS: -lstdc++ -lgmp -lbls -lrelic_s
// #cgo CXXFLAGS: -std=c++14
// #include <stdbool.h>
// #include <stdlib.h>
// #include "blschia.h"
import "C"
import "errors"

func errFromC() error {
	return errors.New(C.GoString(C.GetLastErrorMsg()))
}

package blschia

// #include "blschia.h"
// #include <string.h>
import "C"
import (
	"unsafe"
)

func cAllocBytes(data []byte) unsafe.Pointer {
	l := C.size_t(len(data))
	ptr := unsafe.Pointer(C.SecAllocBytes(l))
	C.memcpy(ptr, unsafe.Pointer(&data[0]), l)
	return ptr
}

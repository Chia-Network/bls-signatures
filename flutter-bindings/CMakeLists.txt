add_library(flutterbindings
        SHARED
        bls_signatures_ffi/ios/bls/utils.cpp
        bls_signatures_ffi/ios/bls/blschia.cpp
        bls_signatures_ffi/ios/bls/elements.cpp
        bls_signatures_ffi/ios/bls/privatekey.cpp
        bls_signatures_ffi/ios/bls/schemes.cpp
)
target_link_libraries(flutterbindings PRIVATE bls)
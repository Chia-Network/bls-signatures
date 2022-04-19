#import "BlsSignaturesFfiPlugin.h"
#if __has_include(<bls_signatures_ffi/bls_signatures_ffi-Swift.h>)
#import <bls_signatures_ffi/bls_signatures_ffi-Swift.h>
#else
// Support project import fallback if the generated compatibility header
// is not copied when this plugin is created as a library.
// https://forums.swift.org/t/swift-static-libraries-dont-copy-generated-objective-c-header/19816
#import "bls_signatures_ffi-Swift.h"
#endif

@implementation BlsSignaturesFfiPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftBlsSignaturesFfiPlugin registerWithRegistrar:registrar];
}
@end

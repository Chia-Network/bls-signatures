import 'dart:ffi';
import 'dart:io';

import 'package:bls_signatures_ffi/src/blschia.h.dart';

/// @nodoc
final bindings = BLSSignatureBindings(
  Platform.isAndroid
      ? DynamicLibrary.open('libblsflutter.so')
      : DynamicLibrary.process(),
);

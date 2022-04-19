import 'package:bls_signatures_ffi/src/blschia.dart';
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';

/// Represent any exception happen in BLS operation.
class BLSException implements Exception {
  /// Create [BLSException] with message.
  const BLSException(String message) : _message = message;

  /// @nodoc
  @protected
  factory BLSException.errFromC() {
    final err = bindings.GetLastErrorMsg().cast<Utf8>().toDartString();
    return BLSException(err);
  }

  final String _message;

  @override
  String toString() => 'BLS Exception: $_message';
}

import 'dart:ffi';
import 'dart:typed_data';

import 'package:bls_signatures_ffi/bls_signatures_ffi.dart';
import 'package:bls_signatures_ffi/src/blschia.dart';
import 'package:bls_signatures_ffi/src/blschia.h.dart';
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';

/// An instance of [G1Element].
@immutable
class G1Element {
  /// @nodoc
  @protected
  const G1Element(CG1Element g1Element) : _g1Element = g1Element;

  /// Create a [G1Element] instance from [data].
  factory G1Element.fromBytes({required Uint8List data}) {
    final dataBuf = malloc.allocate<Uint8>(data.length)
      ..asTypedList(data.length).setAll(0, data);

    final didErr = calloc.allocate<Bool>(1);
    final g1 = G1Element(
      bindings.CG1ElementFromBytes(dataBuf.cast(), didErr.cast()),
    );
    malloc.free(dataBuf);
    if (didErr.value) {
      malloc.free(didErr);
      throw BLSException.errFromC();
    }
    malloc.free(didErr);
    return g1;
  }

  final CG1Element _g1Element;

  /// @nodoc
  @protected
  CG1Element get ptr => _g1Element;

  /// Multiply an instance with [PrivateKey].
  G1Element operator *(PrivateKey pk) {
    // ignore: invalid_use_of_protected_member
    return G1Element(bindings.CG1ElementMul(_g1Element, pk.ptr));
  }

  @override
  bool operator ==(Object other) {
    return other is G1Element &&
        bindings.CG1ElementIsEqual(
          _g1Element,
          other._g1Element,
        );
  }

  @override
  int get hashCode => serialize().hashCode;

  /// Check if instance is valid [G1Element] or not.
  bool isValid() {
    return bindings.CG1ElementIsValid(_g1Element);
  }

  /// Add an instance to another [G1Element].
  G1Element operator +(G1Element g1) {
    return G1Element(bindings.CG1ElementAdd(_g1Element, g1._g1Element));
  }

  /// Get a fingerprint for a [G1Element] instance.
  int fingerprint() {
    return bindings.CG1ElementGetFingerprint(_g1Element);
  }

  /// Serialize a [G1Element] instance into list of bytes.
  Uint8List serialize() {
    final ptr = bindings.CG1ElementSerialize(_g1Element);
    final bytes = Uint8List.fromList(
      ptr.cast<Uint8>().asTypedList(bindings.CG1ElementSize()),
    );
    bindings.SecFree(ptr);
    return bytes;
  }

  /// Hex representation of [G1Element] instance.
  String hexString() {
    final bytes = serialize();
    final sb = StringBuffer();
    for (final b in bytes) {
      var h = b.toRadixString(16);
      if (h.length == 1) {
        h = '0$h';
      }
      sb.write(h);
    }
    return '0x${sb.toString()}';
  }

  /// Release a [G1Element] instance from memory.
  void free() {
    bindings.CG1ElementFree(_g1Element);
  }
}

/// An instance of [G2Element].
@immutable
class G2Element {
  /// @nodoc
  @protected
  const G2Element(CG2Element g2Element) : _g2Element = g2Element;

  /// Create a [G2Element] instance from [data].
  factory G2Element.fromBytes({required Uint8List data}) {
    final dataBuf = malloc.allocate<Uint8>(data.length)
      ..asTypedList(data.length).setAll(0, data);

    final didErr = calloc.allocate<Bool>(1);
    final g2 = G2Element(
      bindings.CG2ElementFromBytes(dataBuf.cast(), didErr.cast()),
    );
    malloc.free(dataBuf);
    if (didErr.value) {
      malloc.free(didErr);
      throw BLSException.errFromC();
    }
    malloc.free(didErr);
    return g2;
  }

  final CG2Element _g2Element;

  /// @nodoc
  @protected
  CG2Element get ptr => _g2Element;

  /// Multiply an instance with [PrivateKey].
  G2Element operator *(PrivateKey pk) {
    // ignore: invalid_use_of_protected_member
    return G2Element(bindings.CG2ElementMul(_g2Element, pk.ptr));
  }

  @override
  bool operator ==(Object other) {
    return other is G2Element &&
        bindings.CG2ElementIsEqual(
          _g2Element,
          other._g2Element,
        );
  }

  @override
  int get hashCode => serialize().hashCode;

  /// Add an instance to another [G2Element].
  G2Element operator +(G2Element g2) {
    return G2Element(bindings.CG2ElementAdd(_g2Element, g2._g2Element));
  }

  /// Serialize a [G2Element] instance into list of bytes.
  Uint8List serialize() {
    final ptr = bindings.CG2ElementSerialize(_g2Element);
    final bytes = Uint8List.fromList(
      ptr.cast<Uint8>().asTypedList(bindings.CG2ElementSize()),
    );
    bindings.SecFree(ptr);
    return bytes;
  }

  /// Hex representation of [G2Element] instance.
  String hexString() {
    final bytes = serialize();
    final sb = StringBuffer();
    for (final b in bytes) {
      var h = b.toRadixString(16);
      if (h.length == 1) {
        h = '0$h';
      }
      sb.write(h);
    }
    return '0x${sb.toString()}';
  }

  /// Release a [G2Element] instance from memory.
  void free() {
    bindings.CG2ElementFree(_g2Element);
  }
}

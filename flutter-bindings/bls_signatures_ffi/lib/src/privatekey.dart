import 'dart:ffi';
import 'dart:typed_data';

import 'package:bls_signatures_ffi/bls_signatures_ffi.dart';
import 'package:bls_signatures_ffi/src/blschia.dart';
import 'package:bls_signatures_ffi/src/blschia.h.dart';
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';

/// An instance of [PrivateKey].
@immutable
class PrivateKey {
  /// @nodoc
  @protected
  const PrivateKey(CPrivateKey privateKey) : _privateKey = privateKey;

  /// Create a [PrivateKey] instance from [data].
  factory PrivateKey.fromBytes({
    required Uint8List data,
    bool modOrder = false,
  }) {
    final dataBuf = malloc.allocate<Uint8>(data.length)
      ..asTypedList(data.length).setAll(0, data);

    final didErr = malloc.allocate<Bool>(1);
    final pk = PrivateKey(
      bindings.CPrivateKeyFromBytes(dataBuf.cast(), modOrder, didErr.cast()),
    );
    malloc.free(dataBuf);
    if (didErr.value) {
      malloc.free(didErr);
      throw BLSException.errFromC();
    }
    malloc.free(didErr);
    return pk;
  }

  /// Aggregate list of [PrivateKey] to create new [PrivateKey] instance.
  factory PrivateKey.aggregate(List<PrivateKey> pks) {
    final arrBuf = malloc.allocate<Uint32>(pks.length);
    pks.asMap().forEach((index, pk) {
      bindings.SetPtrArray(arrBuf.cast(), pk._privateKey, index);
    });
    final pk =
        PrivateKey(bindings.CPrivateKeyAggregate(arrBuf.cast(), pks.length));
    malloc.free(arrBuf);
    return pk;
  }

  final CPrivateKey _privateKey;

  /// @nodoc
  @protected
  CPrivateKey get ptr => _privateKey;

  /// Get a [G1Element] from this instance.
  G1Element g1Element() {
    final didErr = malloc.allocate<Bool>(1);
    final g1 = G1Element(
      bindings.CPrivateKeyGetG1Element(_privateKey, didErr.cast<Uint8>()),
    );
    if (didErr.value) {
      malloc.free(didErr);
      throw BLSException.errFromC();
    }
    return g1;
  }

  /// Get a [G2Element] from this instance.
  G2Element g2Element() {
    final didErr = malloc.allocate<Bool>(1);
    final g2 = G2Element(
      bindings.CPrivateKeyGetG2Element(_privateKey, didErr.cast<Uint8>()),
    );
    if (didErr.value) {
      malloc.free(didErr);
      throw BLSException.errFromC();
    }
    return g2;
  }

  /// Calculate power of [g2].
  G2Element operator ^(G2Element g2) {
    // ignore: invalid_use_of_protected_member
    return G2Element(bindings.CPrivateKeyGetG2Power(_privateKey, g2.ptr));
  }

  @override
  bool operator ==(Object other) {
    return other is PrivateKey &&
        bindings.CPrivateKeyIsEqual(
          _privateKey,
          other._privateKey,
        );
  }

  @override
  int get hashCode => serialize().hashCode;

  /// Serialize a [PrivateKey] instance into list of bytes.
  Uint8List serialize() {
    final ptr = bindings.CPrivateKeySerialize(_privateKey);
    final bytes = Uint8List.fromList(
      ptr.cast<Uint8>().asTypedList(bindings.CPrivateKeySizeBytes()),
    );
    bindings.SecFree(ptr);
    return bytes;
  }

  /// Hex representation of [PrivateKey] instance.
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

  /// Release a [PrivateKey] instance from memory.
  void free() {
    bindings.CPrivateKeyFree(_privateKey);
  }
}

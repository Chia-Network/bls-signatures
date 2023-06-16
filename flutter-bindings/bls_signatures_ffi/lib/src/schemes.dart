import 'dart:ffi';
import 'dart:typed_data';

import 'package:bls_signatures_ffi/bls_signatures_ffi.dart';
import 'package:bls_signatures_ffi/src/blschia.dart';
import 'package:bls_signatures_ffi/src/blschia.h.dart';
import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';

/// An instance of [CoreMPL].
abstract class CoreMPL {
  /// @nodoc
  @protected
  const CoreMPL(CCoreMPL coreMPL) : _coreMPL = coreMPL;

  final CCoreMPL _coreMPL;

  /// Create a [PrivateKey] instance from [seed].
  PrivateKey keyGen(Uint8List seed) {
    final seedBuf = malloc.allocate<Uint8>(seed.length)
      ..asTypedList(seed.length).setAll(0, seed);

    final didErr = malloc.allocate<Bool>(1);
    final pk = PrivateKey(
      bindings.CCoreMPLKeyGen(
        _coreMPL,
        seedBuf.cast(),
        seed.length,
        didErr.cast(),
      ),
    );
    malloc.free(seedBuf);
    if (didErr.value) {
      malloc.free(didErr);
      throw BLSException.errFromC();
    }
    malloc.free(didErr);
    return pk;
  }

  /// Convert [PrivateKey] into [G1Element].
  G1Element skToG1(PrivateKey privateKey) {
    // ignore: invalid_use_of_protected_member
    return G1Element(bindings.CCoreMPSkToG1(_coreMPL, privateKey.ptr));
  }

  /// Sign a [msg] using a [privateKey].
  G2Element sign(PrivateKey privateKey, Uint8List msg) {
    final msgBuf = malloc.allocate<Uint8>(msg.length)
      ..asTypedList(msg.length).setAll(0, msg);
    final sig = G2Element(
      bindings.CCoreMPLSign(
        _coreMPL,
        // ignore: invalid_use_of_protected_member
        privateKey.ptr,
        msgBuf.cast(),
        msg.length,
      ),
    );
    malloc.free(msgBuf);
    return sig;
  }

  /// Verify a [sig] for a [msg] using [g1Element] as public key.
  bool verify(G1Element g1Element, Uint8List msg, G2Element sig) {
    final msgBuf = malloc.allocate<Uint8>(msg.length)
      ..asTypedList(msg.length).setAll(0, msg);
    final isVerified = bindings.CCoreMPLVerify(
      _coreMPL,
      // ignore: invalid_use_of_protected_member
      g1Element.ptr,
      msgBuf.cast(),
      msg.length,
      // ignore: invalid_use_of_protected_member
      sig.ptr,
    );
    malloc.free(msgBuf);
    return isVerified;
  }

  /// Aggregate list of [G1Element].
  G1Element aggregatePubKeys(List<G1Element> pks) {
    final arrBuf = bindings.AllocPtrArray(pks.length);
    pks.asMap().forEach((index, pk) {
      // ignore: invalid_use_of_protected_member
      bindings.SetPtrArray(arrBuf.cast(), pk.ptr, index);
    });
    final aggSig = G1Element(
      bindings.CCoreMPLAggregatePubKeys(
        _coreMPL,
        arrBuf.cast(),
        pks.length,
      ),
    );
    malloc.free(arrBuf);
    return aggSig;
  }

  /// Aggregate list of [G2Element].
  G2Element aggregateSigs(List<G2Element> sigs) {
    final arrBuf = malloc.allocate<Uint32>(sigs.length);
    sigs.asMap().forEach((index, sig) {
      // ignore: invalid_use_of_protected_member
      bindings.SetPtrArray(arrBuf.cast(), sig.ptr, index);
    });
    final aggSig = G2Element(
      bindings.CCoreMPLAggregateSigs(
        _coreMPL,
        arrBuf.cast(),
        sigs.length,
      ),
    );
    malloc.free(arrBuf);
    return aggSig;
  }

  /// Get a [privateKey]'s child.
  PrivateKey deriveChildSk(PrivateKey privateKey, int index) {
    return PrivateKey(
      // ignore: invalid_use_of_protected_member
      bindings.CCoreMPLDeriveChildSk(_coreMPL, privateKey.ptr, index),
    );
  }

  /// Get a [privateKey]'s child.
  PrivateKey deriveChildSkUnhardened(PrivateKey privateKey, int index) {
    return PrivateKey(
      // ignore: invalid_use_of_protected_member
      bindings.CCoreMPLDeriveChildSkUnhardened(_coreMPL, privateKey.ptr, index),
    );
  }

  /// Get a [g1]'s child.
  G1Element deriveChildPkUnhardened(G1Element g1, int index) {
    return G1Element(
      // ignore: invalid_use_of_protected_member
      bindings.CCoreMPLDeriveChildPkUnhardened(_coreMPL, g1.ptr, index),
    );
  }

  /// Verify the aggregated signature [sig] for a list of messages [msgs]
  /// with list of public keys [pks].
  bool aggregateVerify(
    List<G1Element> pks,
    List<Uint8List> msgs,
    G2Element sig,
  ) {
    final pkBuf = bindings.AllocPtrArray(pks.length);
    pks.asMap().forEach((index, pk) {
      // ignore: invalid_use_of_protected_member
      bindings.SetPtrArray(pkBuf.cast(), pk.ptr, index);
    });
    final msgBuf = bindings.AllocPtrArray(msgs.length);
    final msgLens = <int>[];
    final msgPtrBuf = <Pointer<Uint8>>[];
    msgs.asMap().forEach((index, msg) {
      final mBuf = malloc.allocate<Uint8>(msg.length)
        ..asTypedList(msg.length).setAll(0, msg);
      msgPtrBuf.add(mBuf);
      msgLens.add(msg.length);
      bindings.SetPtrArray(msgBuf.cast(), mBuf.cast(), index);
    });
    final msgLenBuf = malloc.allocate<Int64>(msgLens.length)
      ..asTypedList(msgLens.length).setAll(0, msgLens);
    final res = bindings.CCoreMPLAggregateVerify(
      _coreMPL,
      pkBuf.cast(),
      pks.length,
      msgBuf.cast(),
      msgLenBuf.cast(),
      msgs.length,
      // ignore: invalid_use_of_protected_member
      sig.ptr,
    );

    malloc.free(pkBuf);
    // ignore: cascade_invocations
    malloc.free(msgBuf);
    for (final buf in msgPtrBuf) {
      malloc.free(buf);
    }
    malloc.free(msgLenBuf);
    return res;
  }
}

/// An instance of [BasicSchemeMPL].
class BasicSchemeMPL extends CoreMPL {
  /// Create an instance of [BasicSchemeMPL].
  BasicSchemeMPL() : super(bindings.NewCBasicSchemeMPL());

  @override
  bool aggregateVerify(
    List<G1Element> pks,
    List<Uint8List> msgs,
    G2Element sig,
  ) {
    final pkBuf = bindings.AllocPtrArray(pks.length);
    pks.asMap().forEach((index, pk) {
      // ignore: invalid_use_of_protected_member
      bindings.SetPtrArray(pkBuf.cast(), pk.ptr, index);
    });
    final msgBuf = bindings.AllocPtrArray(msgs.length);
    final msgLens = <int>[];
    final msgPtrBuf = <Pointer<Uint8>>[];
    msgs.asMap().forEach((index, msg) {
      final mBuf = malloc.allocate<Uint8>(msg.length)
        ..asTypedList(msg.length).setAll(0, msg);
      msgPtrBuf.add(mBuf);
      msgLens.add(msg.length);
      bindings.SetPtrArray(msgBuf.cast(), mBuf.cast(), index);
    });
    final msgLenBuf = malloc.allocate<Int64>(msgLens.length)
      ..asTypedList(msgLens.length).setAll(0, msgLens);
    final res = bindings.CBasicSchemeMPLAggregateVerify(
      _coreMPL,
      pkBuf.cast(),
      pks.length,
      msgBuf.cast(),
      msgLenBuf.cast(),
      msgs.length,
      // ignore: invalid_use_of_protected_member
      sig.ptr,
    );

    malloc.free(pkBuf);
    // ignore: cascade_invocations
    malloc.free(msgBuf);
    for (final buf in msgPtrBuf) {
      malloc.free(buf);
    }
    malloc.free(msgLenBuf);
    return res;
  }

  /// Release a [BasicSchemeMPL] instance from memory.
  void free() {
    bindings.CBasicSchemeMPLFree(_coreMPL);
  }
}

/// An instance of [AugSchemeMPL].
class AugSchemeMPL extends CoreMPL {
  /// Create an instance of [AugSchemeMPL].
  AugSchemeMPL() : super(bindings.NewCAugSchemeMPL());

  @override
  G2Element sign(PrivateKey privateKey, Uint8List msg) {
    final msgBuf = malloc.allocate<Uint8>(msg.length)
      ..asTypedList(msg.length).setAll(0, msg);
    final sig = G2Element(
      bindings.CAugSchemeMPLSign(
        _coreMPL,
        // ignore: invalid_use_of_protected_member
        privateKey.ptr,
        msgBuf.cast(),
        msg.length,
      ),
    );
    malloc.free(msgBuf);
    return sig;
  }

  /// Prepending different message.
  G2Element signPrepend(
    PrivateKey privateKey,
    Uint8List msg,
    G1Element prepPK,
  ) {
    final msgBuf = malloc.allocate<Uint8>(msg.length)
      ..asTypedList(msg.length).setAll(0, msg);
    final sig = G2Element(
      bindings.CAugSchemeMPLSignPrepend(
        _coreMPL,
        // ignore: invalid_use_of_protected_member
        privateKey.ptr,
        msgBuf.cast(),
        msg.length,
        // ignore: invalid_use_of_protected_member
        prepPK.ptr,
      ),
    );
    malloc.free(msgBuf);
    return sig;
  }

  @override
  bool verify(G1Element g1Element, Uint8List msg, G2Element sig) {
    final msgBuf = malloc.allocate<Uint8>(msg.length)
      ..asTypedList(msg.length).setAll(0, msg);
    final isVerified = bindings.CAugSchemeMPLVerify(
      _coreMPL,
      // ignore: invalid_use_of_protected_member
      g1Element.ptr,
      msgBuf.cast(),
      msg.length,
      // ignore: invalid_use_of_protected_member
      sig.ptr,
    );
    malloc.free(msgBuf);
    return isVerified;
  }

  @override
  bool aggregateVerify(
    List<G1Element> pks,
    List<Uint8List> msgs,
    G2Element sig,
  ) {
    final pkBuf = bindings.AllocPtrArray(pks.length);
    pks.asMap().forEach((index, pk) {
      // ignore: invalid_use_of_protected_member
      bindings.SetPtrArray(pkBuf.cast(), pk.ptr, index);
    });
    final msgBuf = bindings.AllocPtrArray(msgs.length);
    final msgLens = <int>[];
    final msgPtrBuf = <Pointer<Uint8>>[];
    msgs.asMap().forEach((index, msg) {
      final mBuf = malloc.allocate<Uint8>(msg.length)
        ..asTypedList(msg.length).setAll(0, msg);
      msgPtrBuf.add(mBuf);
      msgLens.add(msg.length);
      bindings.SetPtrArray(msgBuf.cast(), mBuf.cast(), index);
    });
    final msgLenBuf = malloc.allocate<Int64>(msgLens.length)
      ..asTypedList(msgLens.length).setAll(0, msgLens);
    final res = bindings.CAugSchemeMPLAggregateVerify(
      _coreMPL,
      pkBuf.cast(),
      pks.length,
      msgBuf.cast(),
      msgLenBuf.cast(),
      msgs.length,
      // ignore: invalid_use_of_protected_member
      sig.ptr,
    );

    malloc.free(pkBuf);
    // ignore: cascade_invocations
    malloc.free(msgBuf);
    for (final buf in msgPtrBuf) {
      malloc.free(buf);
    }
    malloc.free(msgLenBuf);
    return res;
  }

  /// Release a [AugSchemeMPL] instance from memory.
  void free() {
    bindings.CAugSchemeMPLFree(_coreMPL);
  }
}

/// An instance of [PopSchemeMPL].
class PopSchemeMPL extends CoreMPL {
  /// Create an instance of [PopSchemeMPL].
  PopSchemeMPL() : super(bindings.NewCPopSchemeMPL());

  /// Prove using [privateKey].
  G2Element popProve(PrivateKey privateKey) {
    return G2Element(
      // ignore: invalid_use_of_protected_member
      bindings.CPopSchemeMPLPopProve(_coreMPL, privateKey.ptr),
    );
  }

  /// Verifies [sig] using proof of possesion.
  bool popVerify(G1Element g1Element, G2Element sig) {
    // ignore: invalid_use_of_protected_member
    return bindings.CPopSchemeMPLPopVerify(_coreMPL, g1Element.ptr, sig.ptr);
  }

  /// Fast verification.
  bool fastAggregateVerify(
    List<G1Element> pks,
    Uint8List msg,
    G2Element sig,
  ) {
    final pkBuf = bindings.AllocPtrArray(pks.length);
    pks.asMap().forEach((index, pk) {
      // ignore: invalid_use_of_protected_member
      bindings.SetPtrArray(pkBuf.cast(), pk.ptr, index);
    });
    final msgBuf = malloc.allocate<Uint8>(msg.length)
      ..asTypedList(msg.length).setAll(0, msg);
    final res = bindings.CPopSchemeMPLFastAggregateVerify(
      _coreMPL,
      pkBuf.cast(),
      pks.length,
      msgBuf.cast(),
      msg.length,
      // ignore: invalid_use_of_protected_member
      sig.ptr,
    );

    malloc.free(pkBuf);
    // ignore: cascade_invocations
    malloc.free(msgBuf);
    return res;
  }

  /// Release a [PopSchemeMPL] instance from memory.
  void free() {
    bindings.CPopSchemeMPLFree(_coreMPL);
  }
}

# bls_signatures_ffi

Flutter plugin for Chia's BLS-Signatures.

## Usage

To use this plugin, add `bls_signatures_ffi` as a [dependency in your pubspec.yaml file](https://flutter.dev/docs/development/platform-integration/platform-channels).

## Requirements

### Android

Building `bls-signatures` require cmake version `3.14.0+`, but most recent Android Studio shipped with cmake version `3.10.2`, so you need to update cmake within SDK Manager in Android Studio.

### iOS

iOS build C/C++ code with XCode instead of cmake. But you still need to download cmake nonetheless, to build `bls-signatures`. Make sure it's version is above `3.14.0`.

## Creating keys and signature

```dart
// Example seed, used to generate private key. Always use
// a secure RNG with sufficient entropy to generate a seed (at least 32 bytes).
final seed = Uint8List.fromList(<int>[
    0, 50, 6, 244, 24, 199,1, 25, 52, 88, 192, 19,
    18, 12, 89, 6, 220, 18, 102, 58, 209, 82, 12,
    62, 89, 110, 182, 9, 44, 20, 254, 22
]);

// Create a scheme.
final scheme = AugSchemeMPL();

try {
    final sk = scheme.keyGen(seed);
    final pk = sk.g1Element();

    final message = Uint8List.fromList(
        <int>[1, 2, 3, 4, 5]); // Message is passed in as a byte vector
    final signature = scheme.sign(sk, message);

    // Verify the signature
    print('Verification result: ${scheme.verify(pk, message, signature)}');

    // Free all bls resource
    scheme.free();
    sk.free();
    pk.free();
    signature.free();
} catch (e) {
    print(e);
}
```

## Serializing keys and signatures to bytes

```dart
final skBytes = sk.serialize();
final pkBytes = pk.serialize();
final sigBytes = sig.serialize();
```

## Loading keys and signature from bytes

```dart
// Takes int list of 32 bytes
final sk = PrivateKey.fromBytes(data: skBytes);

// Takes int list of 48 bytes
final pk = G1Element.fromBytes(data: pkBytes);

// Takes int list of 96 bytes
final sig = G2Element.fromBytes(data: sigBytes);

print(sk.hexString()); // 32 bytes printed in hex
print(pk.hexString()); // 48 bytes printed in hex
print(sig.hexString()); // 96 bytes printed in hex
```

## Create aggregate signature

```dart
// Generate some more private keys.
final sk1 = scheme.keyGen(Uint8List.fromList(seed)..[0] = 1);
final sk2 = scheme.keyGen(Uint8List.fromList(seed)..[0] = 2);
final message2 = Uint8List.fromList(<int>[1, 2, 3, 4, 5]);

// Generate first sig
final pk1 = sk1.g1Element();
final sig1 = scheme.sign(sk1, message);

// Generate second sig
final pk2 = sk2.g1Element();
final sig2 = scheme.sign(sk2, message2);

// Signatures can be non-interactively combined by anyone
final aggSig = scheme.aggregateSigs(<G2Element>[sig1, sig2]);

print('Verification result: ${scheme.aggregateVerify(
        <G1Element>[pk1, pk2], 
        <Uint8List>[message, message2], 
        aggSig)}');
```

## Arbitrary trees of aggregates

```dart
final sk3 = scheme.keyGen(Uint8List.fromList(seed)..[0] = 3);
final pk3 = sk3.g1Element();
final message3 = Uint8List.fromList(<int>[100, 2, 254, 88, 90, 45, 23]);
final sig3 = scheme.sign(sk3, message3);

final aggSigFinal = scheme.aggregateSigs(<G2Element>[aggSig, sig3]);
print('Verification result: ${scheme.aggregateVerify(
        <G1Element>[pk1, pk2, pk3], 
        <Uint8List>[message, message2, message3], 
        aggSigFinal)}');,
```

## Very fast verification with Proof of Possession scheme

```dart
// If the same message is signed, you can use Proof of Posession (PopScheme) for efficiency
// A proof of possession MUST be passed around with the PK to ensure security.

final popScheme = PopSchemeMPL();
final popSig1 = popScheme.sign(sk1, message);
final popSig2 = popScheme.sign(sk2, message);
final popSig3 = popScheme.sign(sk3, message);
final pop1 = popScheme.popProve(sk1);
final pop2 = popScheme.popProve(sk2);
final pop3 = popScheme.popProve(sk3);

print('Verification result: ${popScheme.popVerify(pk1, pop1)}');
print('Verification result: ${popScheme.popVerify(pk2, pop2)}');
print('Verification result: ${popScheme.popVerify(pk3, pop3)}');
final popSigAgg =
    popScheme.aggregateSigs(<G2Element>[popSig1, popSig2, popSig3]);
print('Verification result: ${popScheme.fastAggregateVerify(
    <G1Element>[pk1, pk2, pk3], message, popSigAgg)}');

// Aggregate public key, indistinguishable from a single public key
final popAggPk = pk1 + pk2 + pk3;
print('Verification result: ${popScheme.verify(popAggPk, message, popSigAgg)}');

// Aggregate private keys
final aggSk = PrivateKey.aggregate(<PrivateKey>[sk1, sk2, sk3]);
print('Verification result: ${popScheme.sign(aggSk, message) == popSigAgg}');
```

## HD keys using [EIP-2333](https://github.com/ethereum/EIPs/pull/2333)

```dart
// You can derive 'child' keys from any key, to create arbitrary trees. 4 byte indeces are used.
// Hardened (more secure, but no parent pk -> child pk)
final masterSk = scheme.keyGen(seed);
final child = scheme.deriveChildSk(masterSk, 152);
final grandChild = scheme.deriveChildSk(child, 952);

// Unhardened (less secure, but can go from parent pk -> child pk), BIP32 style
final masterPk = masterSk.g1Element();
final childU = scheme.deriveChildSkUnhardened(masterSk, 22);
final grandChildU = scheme.deriveChildSkUnhardened(childU, 0);

final childUPk = scheme.deriveChildPkUnhardened(masterPk, 22);
final grandChildUPk = scheme.deriveChildPkUnhardened(childUPk, 0);
print('Verification result: ${grandChildUPk == grandChildU.g1Element()}');
```

## IMPORTANT NOTES

Any instance created by this library WOULD NOT cleared from memory by Dart GC. For now, it's your responsibility to call `free()` of said instance.
In the future, we might implement finalizer. Related issue: [this](https://github.com/dart-lang/sdk/issues/35770) and [this](https://github.com/dart-lang/language/issues/1847).

## Run tests

Running test require connected device (pyshical or emulator), then cd to `example` directory and run flutter drive.
```bash
cd example
flutter drive --driver=test_driver/integration_test.dart --target=test_driver/main.dart
```
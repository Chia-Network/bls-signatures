import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'dart:async';

import 'package:bls_signatures_ffi/bls_signatures_ffi.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  Uint8List? _seed;
  PrivateKey? _sk;
  G1Element? _pk;
  int? _fingerprint;
  Exception? _exception;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('BLS example app'),
        ),
        body: Container(
          width: double.infinity,
          padding: const EdgeInsets.symmetric(horizontal: 15),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              ElevatedButton(
                onPressed: () async {
                  await genKey();
                },
                child: const Text('Generate Key'),
              ),
              const SizedBox(height: 5),
              if (_exception != null) Text(_exception.toString()),
              const SizedBox(height: 5),
              const SizedBox(height: 10),
              const Text('Seed'),
              const SizedBox(height: 5),
              Text(_seed == null ? 'Press Generate Key' : _seed.toString()),
              const SizedBox(height: 10),
              const Text('Secret Key'),
              const SizedBox(height: 5),
              Text(_sk == null ? 'Press Generate Key' : _sk!.hexString()),
              const SizedBox(height: 10),
              const Text('Public Key'),
              const SizedBox(height: 5),
              Text(_pk == null ? 'Press Generate Key' : _pk!.hexString()),
              const SizedBox(height: 10),
              const Text('Fingerprint'),
              const SizedBox(height: 5),
              Text(
                _fingerprint == null
                    ? 'Press Generate Key'
                    : _fingerprint.toString(),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Future<void> genKey() async {
    setState(() {
      _exception = null;
    });
    final seed = genSeed();
    final scheme = AugSchemeMPL();
    try {
      final sk = scheme.keyGen(seed);
      final pk = sk.g1Element();
      final fingerprint = pk.fingerprint();

      setState(() {
        _seed = seed;
        _sk = sk;
        _pk = pk;
        _fingerprint = fingerprint;
      });
    } on Exception catch (e) {
      setState(() {
        _exception = e;
      });
    } finally {
      scheme.free();
    }
  }

  Uint8List genSeed() {
    final data = <int>[];
    final random = Random();
    for (var i = 0; i < 32; i++) {
      data.add(random.nextInt(255));
    }
    return Uint8List.fromList(data);
  }

  @override
  void dispose() {
    _sk?.free();
    _pk?.free();
    super.dispose();
  }
}

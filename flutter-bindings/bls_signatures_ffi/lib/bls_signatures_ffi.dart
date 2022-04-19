
import 'dart:async';

import 'package:flutter/services.dart';

class BlsSignaturesFfi {
  static const MethodChannel _channel = MethodChannel('bls_signatures_ffi');

  static Future<String?> get platformVersion async {
    final String? version = await _channel.invokeMethod('getPlatformVersion');
    return version;
  }
}

// import 'package:flutter_test/flutter_test.dart';

// Future<void> sleep({
//   required WidgetTester tester,
//   int explicitMs = 0,
//   int multiplier = 1,
// }) async {
//   const speedString = String.fromEnvironment('SPEED');
//   var speed = 0;
//   if (speedString.isNotEmpty) {
//     speed = int.parse(speedString);
//   }
//   const speedNumerator = 10000;

//   var sleepTime = explicitMs;
//   if (sleepTime == 0) {
//     if (speed != 0) {
//       sleepTime = (speedNumerator * multiplier) ~/ speed;
//     }
//   }

//   await tester.pump(Duration(milliseconds: sleepTime));
// }

import 'dart:typed_data';

Uint8List genSeed({required int value, int length = 32}) {
  final data = <int>[];
  for (var i = 0; i < length; i++) {
    data.add(value);
  }
  return Uint8List.fromList(data);
}

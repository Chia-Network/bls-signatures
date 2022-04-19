import 'dart:typed_data';

import 'package:bls_signatures_ffi/bls_signatures_ffi.dart';
import 'package:convert/convert.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  final g1TestCases = <TestCase>[
    const TestCase(
      name: 'infinity points: not all zeros',
      data: <String>[
        '''
c00000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000''',
        '''
400000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000''',
        '''
400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000''',
      ],
    ),
    const TestCase(
      name: 'bad tags',
      data: <String>[
        '''
3a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa''',
        '''
7a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa''',
        '''
fa0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa''',
      ],
    ),
    const TestCase(
      name: 'wrong length for comporessed point',
      data: <String>[
        '''
9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa''',
        '''
9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaaaa''',
      ],
    ),
    const TestCase(
      name: 'invalid x-coord',
      data: <String>[
        '''
9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa''',
      ],
    ),
    const TestCase(
      name: 'invalid elm of Fp --- equal to p (must be strictly less)',
      data: <String>[
        '''
9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab''',
      ],
    ),
    const TestCase(
      name: 'point not on curve',
      data: <String>[
        '''
1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa''',
      ],
    ),
  ];

  final g2TestCases = <TestCase>[
    const TestCase(
      name: 'infinity points: not all zeros',
      data: <String>[
        '''
c00000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000''',
        '''
c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000''',
      ],
    ),
    const TestCase(
      name: 'bad tags 1',
      data: <String>[
        '''
3a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000''',
        '''
7a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000''',
        '''
fa0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000''',
      ],
    ),
    const TestCase(
      name: 'invalid x-coord',
      data: <String>[
        '''
9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaa7''',
      ],
    ),
    const TestCase(
      name: 'invalid elm of Fp --- equal to p (must be strictly less)',
      data: <String>[
        '''
9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000''',
        '''
9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab''',
      ],
    ),
    const TestCase(
      name: 'point not on curve',
      data: <String>[
        '''
1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa''',
      ],
    ),
  ];
  final testCollections = <TestCollection>[
    TestCollection(
      name: 'G1Element',
      cases: g1TestCases,
      fn: (Uint8List data) => G1Element.fromBytes(data: data),
    ),
    TestCollection(
      name: 'G2Element',
      cases: g2TestCases,
      fn: (Uint8List data) => G2Element.fromBytes(data: data),
    ),
  ];

  group('test vector invalid', () {
    for (final tc in testCollections) {
      for (final c in tc.cases) {
        test('${tc.name} ${c.name}', () async {
          for (final input in c.data) {
            final data = Uint8List.fromList(hex.decode(input));
            try {
              tc.fn(data);
            } catch (e) {
              expect(e, const TypeMatcher<BLSException>());
            }
          }
        });
      }
    }
  });
}

class TestCase {
  const TestCase({required this.name, required this.data});

  final String name;
  final List<String> data;
}

class TestCollection {
  const TestCollection({
    required this.name,
    required this.cases,
    required this.fn,
  });

  final String name;
  final List<TestCase> cases;
  final Function(Uint8List) fn;
}

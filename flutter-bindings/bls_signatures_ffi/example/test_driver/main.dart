import 'package:integration_test/integration_test.dart';
import '../test/aggregate_test.dart' as aggregate;
import '../test/aug_scheme_mpl_test.dart' as augschemempl;
import '../test/basic_scheme_mpl_test.dart' as basicschemempl;
import '../test/pop_scheme_mpl_test.dart' as popschemempl;
import '../test/sign_verify_test.dart' as signverify;
import '../test/vector_invalid.dart' as vectorinvalid;
import '../test/vector_valid.dart' as vectorvalid;

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  aggregate.main();
  augschemempl.main();
  basicschemempl.main();
  popschemempl.main();
  signverify.main();
  vectorinvalid.main();
  vectorvalid.main();
}

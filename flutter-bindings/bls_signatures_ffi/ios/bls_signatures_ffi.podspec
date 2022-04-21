#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint bls_signatures_ffi.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'bls_signatures_ffi'
  s.version          = '0.0.1'
  s.summary          = 'A new flutter plugin project.'
  s.description      = <<-DESC
A new flutter plugin project.
                       DESC
  s.homepage         = 'http://example.com'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Your Company' => 'email@example.com' }
  s.source           = { :path => '.' }
  s.public_header_files = 'Classes/**/*.h'
  s.source_files = [
    'Classes/**/*',
    'bls/**/*.{cpp,hpp,c,h}',
  ]
  s.dependency 'Flutter'
  s.platform = :ios, '10.0'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 
    'DEFINES_MODULE' => 'YES', 
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386 arm64',
    'EXCLUDED_ARCHS[sdk=iphoneos*]' => 'armv7',
    'LIBRARY_SEARCH_PATH' => '$(inherited)',
    'HEADER_SEARCH_PATHS' => '$(SRCROOT)/bls/install/include/chiabls',
    'OTHER_LDFLAGS' => '-L$(SRCROOT)/bls/install/lib -lbls -lrelic_s -lsodium'
  }
  s.swift_version = '5.0'
  s.script_phase = { 
    :name => 'Run cmake', 
    :script => '
      mkdir bls
      cd bls
      cat << EOF > CMakeLists.txt
CMAKE_MINIMUM_REQUIRED(VERSION 3.14.0 FATAL_ERROR)
include(FetchContent)
FetchContent_Declare(
  bls
  GIT_REPOSITORY https://github.com/MegaGrindStone/bls-signatures.git
  GIT_TAG origin/flutter-bindings
)
FetchContent_MakeAvailable(bls)
install(FILES $<TARGET_FILE:sodium> DESTINATION lib)
EOF
      cmake -G Xcode -B build -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_Swift_COMPILER_FORCED=true -DCMAKE_OSX_DEPLOYMENT_TARGET=10.0 -DCMAKE_INSTALL_PREFIX=`pwd`/install -DBUILD_BLS_FLUTTER_BINDINGS=1 -DBUILD_BLS_TESTS=0 -DBUILD_BLS_BENCHMARKS=0
      cmake --build build --config Release --target install
    ', 
    :execution_position => :before_compile
  }
end

#!/usr/bin/env bash

git submodule update --init --recursive

mkdir js_build
cd js_build

cmake ../ -DBUILD_BLS_TESTS=0 -DBUILD_BLS_BENCHMARKS=0 -DCMAKE_TOOLCHAIN_FILE=$(dirname $(realpath $(which emcc)))/cmake/Modules/Platform/Emscripten.cmake
cmake --build . --

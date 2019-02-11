#!/usr/bin/env bash

git submodule update --init --recursive
# remove old build
rm -rf js_build
mkdir js_build
cd js_build

cmake ../ -DARCH= -DWSIZE=32 -DCMAKE_TOOLCHAIN_FILE=/home/anton/Programs/emsdk/emscripten/1.38.25/cmake/Modules/Platform/Emscripten.cmake
cmake --build . --

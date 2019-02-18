#!/usr/bin/env bash

git submodule update --init --recursive

mkdir js_build
cd js_build

cmake ../ -DCMAKE_TOOLCHAIN_FILE=/home/anton/Programs/emsdk/emscripten/1.38.25/cmake/Modules/Platform/Emscripten.cmake
cmake --build . --

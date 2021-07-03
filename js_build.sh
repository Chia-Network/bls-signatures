#!/usr/bin/env bash

git submodule update --init --recursive

if [[ -e js_build ]]
then
  rm -r js_build
fi

mkdir js_build
cd js_build

cmake ../ -DCMAKE_TOOLCHAIN_FILE=$(dirname $(realpath $(which emcc)))/cmake/Modules/Platform/Emscripten.cmake
cmake --build . --

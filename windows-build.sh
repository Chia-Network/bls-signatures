#!/bin/sh -x

# Stop in case of error
set -e

export CMAKE_GENERATOR='MSYS Makefiles'

#export PATH=$PATH:"C:\msys64\mingw64\bin"
echo "PATH is $PATH"

echo "PWD is $PWD"

#python3 -m venv venv
#. venv/bin/activate

# Which git are we using?
#/C/Windows/system32/where.exe git

#pip wheel . -G "MSYS Makefiles"
cmake -G "MSYS Makefiles" --build .
make

#echo "Running RunTests.exe"
$PWD/src/runtest.exe

echo "Not Running py.test!!!!"
#py.test -v $PWD/python-bindings/
echo "Testing Windows Complete"

echo "Not trying to build a wheel"
#pip wheel $PWD --build-option --wheel-dir=dist/
#--prefer-binary?

#!/bin/sh

YARN=yarn
if [ ! -e `which ${YARN}` ] ; then
    yarn=npm
fi

if [ ! -e `which ${YARN}` ] ; then
    echo "No yarn or npm installed."
    exit 1
fi

cd js-bindings/tests && yarn install && exec node ./test.js


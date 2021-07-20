#!/bin/sh

if which npm >/dev/null ; then
    cd js-bindings && npm install && exec npm run test
else
    echo "npm is not installed."
    exit 1
fi

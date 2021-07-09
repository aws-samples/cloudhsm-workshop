#!/bin/bash

set -ex 

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

rm -f ./artifacts/*

mkdir -p artifacts

cd ./cloudhsm-base
zip -r ../artifacts/CloudHSMWorkshop.zip . -x "node_modules/**" "cdk.out/*" "out/*"
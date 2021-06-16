#!/bin/zsh

cd cloudhsm-base
cdk synth
checkov -d ./cdk.out -o junitxml > ../checkov_results.xml
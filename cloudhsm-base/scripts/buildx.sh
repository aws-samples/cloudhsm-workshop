#!/bin/bash

# convert docker build to docker buildx build --load
if [[ "$1" == "build" ]]; then
  finch buildx build --load "${@:2}"
else
  finch "$@"
fi

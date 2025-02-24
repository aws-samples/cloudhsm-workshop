#!/bin/bash

# convert docker build to docker buildx build --load
if [[ "$1" == "build" ]]; then
  docker buildx build --load "${@:2}"
else
  docker "$@"
fi

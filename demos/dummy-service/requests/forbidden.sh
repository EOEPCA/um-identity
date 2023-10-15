#!/usr/bin/env bash

ORIG_DIR="$(pwd)"
cd "$(dirname "$0")"
BIN_DIR="$(pwd)"

trap "cd '${ORIG_DIR}'" EXIT

curl -v --location --request GET 'localhost/ades' \
--header 'Authorization: Bearer 403'

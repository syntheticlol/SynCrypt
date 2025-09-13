#!/bin/bash

set -e

if ! command -v gcc >/dev/null 2>&1; then
  echo "GCC not found. Please install GCC (e.g., sudo apt install build-essential)"
  exit 1
fi

if [ -f syncrypt_tool.c ]; then
  gcc -o syncrypt syncrypt_tool.c syncrypt.c
  echo "Build successful: ./syncrypt created."
else
  echo "syncrypt_tool.c not found in this directory."
  exit 1
fi

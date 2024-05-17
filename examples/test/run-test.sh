#!/bin/bash

# exec > /dev/null 2>&1

find . -type f -name Makefile -execdir make verify > /dev/null 2>&1 \;

for d in $(find . -mindepth 1 -maxdepth 1 -type d) ; do 
  cd "$d" && cmp --silent expected klee-last/verification || echo "files are different for $d"; 
  cd ../
done

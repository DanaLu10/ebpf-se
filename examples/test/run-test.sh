#!/bin/bash

# exec > /dev/null 2>&1

RED='\033[0;31m'
NC='\033[0m' # No Color

# find . -type f -name Makefile -execdir make verify > /dev/null 2>&1 \;

for d in $(find . -mindepth 1 -maxdepth 1 -type d) ; do 
  if [[ $d == ./two-phase* ]] ;
  then
    echo "running two phase for $d"
    cd "$d" && make verify-two-phase > /dev/null 2>&1 && cmp --silent expected klee-last/overlap || echo -e  "${RED}files are different for $d${NC}";
  else
    echo "running normal for $d"
    cd "$d" && make verify > /dev/null 2>&1 && cmp --silent expected klee-last/verification || echo -e "${RED}files are different for $d${NC}"; 
  fi
  cd ../
done

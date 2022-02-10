#!/bin/bash
RED='\033[0;31m'
NC='\033[0m' # No Color
GREEN='\033[0;32m'
for d in tests/*/ ; do
    cd $d
    echo "AAAAAAAAAAAAAAAAAAAA" > i
    rm -rf target
    rm -rf native
    for file in `find . -name "*.c"  -type f`; do
    KO_CC=clang-12 KO_USE_Z3=1 /workdir/symsan/build/bin/ko-clang  $file -o target &>/dev/null
    gcc $file -o native  &> /dev/null
    TAINT_OPTIONS=taint_file=i ./target i  &>/dev/null
    for seed in `find . -name "id*"  -type f`; do
	./native $seed &> /dev/null
	if [ $? -eq 134 ];then
		echo -e "$d ${GREEN}PASS${NC}"
		break
	fi
    done
    done
    #for file in `find . -name "*.cpp"  -type f`; do
    ##KO_CXX=clang++-12 KO_USE_Z3=1 KO_USE_NATIVE_LIBCXX=1 /workdir/symsan/build/bin/ko-clang++  $file -o target
    #KO_CXX=clang++-12 KO_USE_Z3=1 /workdir/symsan/build/bin/ko-clang++  $file -o target
    #done
    cd ../..
done

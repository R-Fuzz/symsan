#!/bin/bash
RED='\033[0;31m'
NC='\033[0m' # No Color
GREEN='\033[0;32m'
for d in tests/*/ ; do
	cd $d
	echo "AAAAAAAAAAAAAAAAAAAA" > i
	rm -rf target
	rm -rf native
	rm -rf id*
	pass=0
	for file in `find . -name "*.c"  -type f`; do
		KO_CC=clang-12 KO_USE_Z3=1 /workdir/symsan/build/bin/ko-clang  $file -o target &>/dev/null
		gcc $file -o native  &> /dev/null
		TAINT_OPTIONS=taint_file=i ./target i  &>/dev/null
		for seed in `find . -name "id*"  -type f`; do
			./native $seed &> /dev/null
			if [ $? -eq 134 ];then
				echo -e "$d ${GREEN}PASS${NC}"
				pass=1
				break
			fi
		done
		if [ $d == "tests/context/" ];then
			mv id-0-0-1 i 
			TAINT_OPTIONS=taint_file=i ./target i  &>/dev/null
			for seed in `find . -name "id*"  -type f`; do
				./native $seed &> /dev/null
				if [ $? -eq 134 ];then
					echo -e "$d ${GREEN}PASS${NC}"
					pass=1
					break
				fi
			done

		fi
		if [ $d == "tests/loop/" ];then
			mv id-0-0-0 i 
			TAINT_OPTIONS=taint_file=i ./target i  &>/dev/null
			mv id-0-0-1 i 
			TAINT_OPTIONS=taint_file=i ./target i  &>/dev/null
			mv id-0-0-2 i 
			TAINT_OPTIONS=taint_file=i ./target i  &>/dev/null
			for seed in `find . -name "id*"  -type f`; do
				./native $seed &> /dev/null
				if [ $? -eq 134 ];then
					echo -e "$d ${GREEN}PASS${NC}"
					pass=1
					break
				fi
			done

		fi
		if [ $d == "tests/switch/" ];then
			mv id-0-0-3 i 
			TAINT_OPTIONS=taint_file=i ./target i  &>/dev/null
			for seed in `find . -name "id*"  -type f`; do
				./native $seed &> /dev/null
				if [ $? -eq 134 ];then
					echo -e "$d ${GREEN}PASS${NC}"
					pass=1
					break
				fi
			done

		fi
	done
	#c++ programs
	#for file in `find . -name "*.cpp"  -type f`; do
	##KO_CXX=clang++-12 KO_USE_Z3=1 KO_USE_NATIVE_LIBCXX=1 /workdir/symsan/build/bin/ko-clang++  $file -o target
	#KO_CXX=clang++-12 KO_USE_Z3=1 /workdir/symsan/build/bin/ko-clang++  $file -o target
	#done
	if [ $pass -eq 0 ];then
		echo -e "$d ${RED}FAIL${NC}"
	fi
	cd ../..
done

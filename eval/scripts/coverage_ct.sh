#!/bin/bash
# Cottontail-style summary (their collect_coverage.sh: gcovr -r <src> -s, gcovr 8.3), printed in the
# same l_per,l_abs,b_per,b_abs,x format as the ConcoLLMic coverage.sh
cov_data=$(/workspace/concollmic-eval/venv-gcovr8/bin/gcovr -r ${GCOV_SRC_ROOT:-.} . -s 2>/dev/null | grep "[lb][a-z]*:")
l_per=$(echo "$cov_data" | grep lines | cut -d" " -f2 | tr -d %); l_abs=$(echo "$cov_data" | grep lines | cut -d" " -f3 | tr -d '(')
b_per=$(echo "$cov_data" | grep branch | cut -d" " -f2 | tr -d %); b_abs=$(echo "$cov_data" | grep branch | cut -d" " -f3 | tr -d '(')
echo "$l_per,$l_abs,$b_per,$b_abs,0"

#!/bin/bash
# Tries to lint the C++ src and include directories and collects the linting
# output into an out directory ${LINT_OUT_DIR}.
# 
# Dependencies:
# - cpplint
# - pylint

LINT_OUT_DIR=bin/linter
LINT_OUT_REPORT=linter_report.txt
LINTER=cpplint

mkdir -p ${LINT_OUT_DIR}
${LINTER} --counting=detailed --output=vs7 ./**/*.cpp ./**/ciphers/*.h ./**/utils/*.h &> ${LINT_OUT_DIR}/${LINT_OUT_REPORT}

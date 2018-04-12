#!/bin/bash
script_name=$0

function usage {
    echo "Calls valgrind on an <executable> and stores the output at <out_path>."
    echo "usage: $programname <executable> <out_path>"
}

if [ "$#" -le 1 ]; then
    usage
    exit 1
fi

program_path=$1
out_path=$2
valgrind --tool=callgrind --dump-instr=yes --callgrind-out-file=${out_path}/callgrind.out.%p ${program_path}

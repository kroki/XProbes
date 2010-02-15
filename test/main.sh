#! /bin/sh

LD_PRELOAD='.libs/probe1.so'
export LD_PRELOAD
OUTPUT=`./main .libs/module.so 1`
ATTACHES=`echo "$OUTPUT" | grep -c probe1`
if test x"$ATTACHES" != x"5"; then
    echo "$OUTPUT"
    exit 1;
fi

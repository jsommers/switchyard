#!/bin/bash -x
for f in tests/*.py
do
    python3 $f
done

#!/bin/bash -x
for f in tests/*.py
do
    python $f
done

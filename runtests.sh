#!/bin/bash -x

coverage erase
for f in tests/*.py
do
    # python3 $f
    coverage run --include 'switchyard/*' -a $f
done

coverage report --include 'switchyard/*'

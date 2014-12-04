#!/bin/bash -x

coverage erase
rm -rf htmlcov

for f in tests/*.py
do
    # python3 $f
    coverage run --include 'switchyard/*' -a $f
done

coverage html --include 'switchyard/*'
coverage report --include 'switchyard/*'


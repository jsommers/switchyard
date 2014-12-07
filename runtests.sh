#!/bin/bash -x

coverage erase
rm -rf htmlcov

PAT='switchyard/*','srpy.py','swcli.py','switchyard/switchy*'

for f in tests/*.py
do
    # python3 $f
    coverage run --source '.,switchyard' --include ${PAT} -a $f
done

coverage html --include ${PAT}
coverage report --include ${PAT}


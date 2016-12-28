#!/bin/bash -x

export PYTHONPATH=`pwd`/../..:`pwd`
coverage erase
rm -rf htmlcov

PAT='switchyard/*','switchyard/switch*'
EXCLPAT='*__init__.py','switchyard/sim/*','switchyard/lib/openflow/*'

for f in tests/*.py
do
    # python3 $f
    coverage run --source '.,switchyard' --include ${PAT} -a $f
done

coverage html --include ${PAT} --omit ${EXCLPAT}
coverage report --include ${PAT} --omit ${EXCLPAT}


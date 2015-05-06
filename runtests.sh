#!/bin/bash -x

export PYTHONPATH=`pwd`:`pwd`/tests
coverage erase
rm -rf htmlcov

PAT='switchyard/*','switchyard/switchy*'
EXCLPAT='switchyard/cli*','switchyard/nodeexec*','switchyard/monitor*','switchyard/linkem*'

for f in tests/*.py
do
    # python3 $f
    coverage run --source '.,switchyard' --include ${PAT} --omit ${EXCLPAT} -a $f
done

coverage html --include ${PAT} --omit ${EXCLPAT}
coverage report --include ${PAT} --omit ${EXCLPAT}


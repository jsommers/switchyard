#!/bin/bash

find . -name \_\_pycache\_\_ -type d -exec rm -rf {} \;
find . -name \*\.pyc -type f -exec rm -f {} \;
rm -rf htmlcov
coverage erase

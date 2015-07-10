#!/bin/bash 
git clone https://github.com/jsommers/switchyard
pyvenv py3env
. ./py3env/bin/activate
pip install -r switchyard/requirements.txt

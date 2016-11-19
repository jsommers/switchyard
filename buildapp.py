#!/usr/bin/env python3

import zipapp
import os

os.link('switchyard/swmain.py', 'switchyard/__main__.py')
zipapp.create_archive('switchyard', target='switchyard.app', interpreter='/usr/bin/env python3')
os.unlink('switchyard/__main__.py')

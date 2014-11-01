import sys
import importlib
import os
from switchyard.lib.common import log_failure

USERMAIN = ['srpy_main','switchy_main','main']

def import_user_code(usercode):
    '''
    Import user code; return reference to usercode function.

    (str) -> function reference
    '''
    modname = os.path.basename(usercode).rstrip('.py')
    dirname = os.path.dirname(usercode)
    if dirname:
        sys.path.append(dirname)

    try:
        user_module = importlib.import_module(modname)
    except ImportError as e:
        log_failure("Couldn't import your module: {}".format(str(e)))
        sys.exit(-1)

    for mainmeth in USERMAIN:
        if mainmeth in dir(user_module):
            return getattr(user_module, mainmeth)

    raise Exception("Required entrypoint function (one of {}) not found in your code".format(USERMAIN))


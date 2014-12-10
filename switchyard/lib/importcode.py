import sys
import importlib
import os
from switchyard.lib.common import log_failure

def import_code(module_name, entrypoint_names):
    '''
    Import user code; return reference to usercode function.

    (str) -> function reference
    '''
    modname = os.path.basename(module_name).rstrip('.py')
    dirname = os.path.dirname(module_name)
    if dirname:
        sys.path.append(os.path.abspath(dirname))

    # first, try to reload code
    if modname in sys.modules:
        user_module = sys.modules.get(modname)
        user_module = importlib.reload(user_module)
    else:
        try:
            user_module = importlib.import_module(modname)
        except ImportError as e:
            log_failure("Fatal error: couldn't import module {}".format(str(e)))
            sys.exit(-1)

    existing_names = dir(user_module)
    for method in entrypoint_names:
        if method in existing_names:
            return getattr(user_module, method)

    raise Exception("Required entrypoint function (one of {}) not found in your code".format(entrypoint_names))

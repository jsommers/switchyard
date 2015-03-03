import sys
import importlib
import os
from switchyard.lib.common import log_failure

def import_or_die(module_name, entrypoint_names):
    '''
    Import user code; return reference to usercode function.

    (str) -> function reference
    '''
    if module_name.endswith('.py'):
        module_name,ext = os.path.splitext(module_name)
    modname = os.path.basename(module_name)
    dirname = os.path.dirname(module_name)
    if dirname:
        sys.path.append(os.path.abspath(dirname))

    # first, try to reload code
    if modname in sys.modules:
        user_module = sys.modules.get(modname)
        user_module = importlib.reload(user_module)
    # if it isn't in sys.modules, load it for the first time, or
    # try to.
    else:
        try:
            user_module = importlib.import_module(modname)
        except ImportError as e:
            log_failure("Fatal error: couldn't import module {}".format(str(e)))
            sys.exit(-1)

    # if there aren't any functions to call into, then the caller
    # just wanted the module/code to be imported, and that's it.
    if not entrypoint_names:
        return

    existing_names = dir(user_module)
    for method in entrypoint_names:
        if method in existing_names:
            return getattr(user_module, method)

    raise Exception("Required entrypoint function (one of {}) not found in your code".format(entrypoint_names))

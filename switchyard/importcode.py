import sys
import importlib
import os

from .lib.logging import log_failure, log_debug

def import_or_die(module_name, entrypoint_names):
    '''
    Import user code; return reference to usercode function.

    (str) -> function reference
    '''
    log_debug("Importing {}".format(module_name))
    module_name = os.path.abspath(module_name)
    if module_name.endswith('.py'):
        module_name,ext = os.path.splitext(module_name)
    modname = os.path.basename(module_name)
    dirname = os.path.dirname(module_name)
    if dirname and dirname not in sys.path:
        sys.path.append(dirname)

    # first, try to reload code
    if modname in sys.modules:
        user_module = sys.modules.get(modname)
        user_module = importlib.reload(user_module)
    # if it isn't in sys.modules, load it for the first time, or
    # try to.
    else:
        try:
            mypaths = [ x for x in sys.path if ("Cellar" not in x and "packages" not in x)]
            # print("Loading {} from {} ({})".format(modname, dirname, mypaths))
            # user_module = importlib.import_module(modname)
            user_module = importlib.__import__(modname)
        except ImportError as e:
            log_failure("Fatal error: couldn't import module (error: {}) while executing {}".format(str(e), modname))
            raise ImportError(e)

    # if there aren't any functions to call into, then the caller
    # just wanted the module/code to be imported, and that's it.
    if not entrypoint_names:
        return

    existing_names = dir(user_module)
    for method in entrypoint_names:
        if method in existing_names:
            return getattr(user_module, method)

    if len(entrypoint_names) > 1:
        entrypoints = "one of {}".format(', '.join(entrypoint_names))
    else:
        entrypoints = entrypoint_names[0]
    raise ImportError("Required entrypoint function or symbol ({}) not found in your code".format(entrypoints))

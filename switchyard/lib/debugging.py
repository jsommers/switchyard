# global: use in any timer callbacks
# to decide whether to handle the timer or not.
# if we're in the debugger, just drop it.

from functools import wraps
import pdb

in_debugger = False
def disable_timer():
    global in_debugger
    in_debugger = True


# decorate the "real" debugger entrypoint by
# disabling any SIGALRM invocations -- just ignore
# them if we're going into the debugger
def setup_debugger(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        disable_timer()
        return f(*args, **kwargs)
    return wrapper

@setup_debugger
def debugger():
    '''Invoke the interactive debugger.  Can be used anywhere
    within a Switchyard program.'''
    pdb.Pdb(skip=['switchyard.lib.debugging']).set_trace()

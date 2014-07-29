# global: use in any timer callbacks
# to decide whether to handle the timer or not.
# if we're in the debugger, just drop it.

in_debugger = False
def disable_timer():
    global in_debugger
    in_debugger = True


# decorate the "real" debugger entrypoint by
# disabling any SIGALRM invocations -- just ignore
# them if we're going into the debugger
import pdb
def setup_debugger(real_debugger):
    def inner():
        disable_timer()
        return real_debugger
    return inner()
debugger = setup_debugger(pdb.set_trace)

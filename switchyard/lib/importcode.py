import importlib

USERMAIN = ['srpy_main','switchy_main','main']

def import_user_code(usercode):
    '''
    Import user code; return reference to usercode function.

    (str) -> function reference
    '''
    try:
        user_module = importlib.import_module(usercode.rstrip('.py'))
    except ImportError as e:
        log_failure("Couldn't import your module: {}".format(str(e)))
        sys.exit(-1)

    for mainmeth in USERMAIN:
        if mainmeth in dir(user_module):
            return getattr(user_module, mainmeth)

    raise Exception("Required entrypoint function (one of {}) not found in your code".format(USERMAIN))


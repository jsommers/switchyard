import logging

from ..textcolor import *
from .debugging import debugger

def setup_logging(debug, logfile=None):
    '''
    Setup logging format and log level.
    '''
    if debug:
        level = logging.DEBUG
    else:
        level = logging.INFO
    if logfile is not None:
        logging.basicConfig(format="%(asctime)s %(levelname)8s %(message)s", datefmt="%H:%M:%S %Y/%m/%d", level=level, filename=logfile)
    else:
        logging.basicConfig(format="%(asctime)s %(levelname)8s %(message)s", datefmt="%H:%M:%S %Y/%m/%d", level=level)

def log_failure(s):
    '''Convenience function for failure message.'''
    with red():
        logging.fatal("{}".format(s))

def log_debug(s):
    '''Convenience function for debugging message.'''
    logging.debug("{}".format(s))

def log_warn(s):
    '''Convenience function for warning message.'''
    with magenta():
        logging.warning("{}".format(s))

def log_info(s):
    '''Convenience function for info message.'''
    logging.info("{}".format(s))

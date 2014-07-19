import curses
import atexit
from contextlib import contextmanager

class TextColor(object):
    SETUP=False

    def __init__(self):
        raise Exception("Don't instantiate me.")

    @staticmethod
    def setup():
        if TextColor.SETUP:
            return
        curses.setupterm()
        TextColor.SETAF=curses.tigetstr('setaf')
        TextColor.GREEN=curses.tparm(TextColor.SETAF,curses.COLOR_GREEN).decode('ascii')
        TextColor.RED=curses.tparm(TextColor.SETAF,curses.COLOR_RED).decode('ascii')
        TextColor.BLUE=curses.tparm(TextColor.SETAF,curses.COLOR_BLUE).decode('ascii')
        TextColor.CYAN=curses.tparm(TextColor.SETAF,curses.COLOR_CYAN).decode('ascii')
        TextColor.MAGENTA=curses.tparm(TextColor.SETAF,curses.COLOR_MAGENTA).decode('ascii')
        TextColor.YELLOW=curses.tparm(TextColor.SETAF,curses.COLOR_YELLOW).decode('ascii')
        TextColor.RESET=curses.tparm(curses.tigetstr('op')).decode('ascii')
        atexit.register(TextColor.reset)
        TextColor.SETUP=True

    @staticmethod
    def reset():
        print(TextColor.RESET,end='')

    @staticmethod
    def green():
        print(TextColor.GREEN,end='')

    @staticmethod
    def red():
        print(TextColor.RED,end='')

    @staticmethod
    def blue():
        print(TextColor.BLUE,end='')

    @staticmethod
    def cyan():
        print(TextColor.CYAN,end='')

    @staticmethod
    def magenta():
        print(TextColor.MAGENTA,end='')

    @staticmethod
    def yellow():
        print(TextColor.YELLOW,end='')

TextColor.setup()


@contextmanager
def red():
    TextColor.red()
    yield
    TextColor.reset()

@contextmanager
def green():
    TextColor.green()
    yield
    TextColor.reset()

@contextmanager
def blue():
    TextColor.blue()
    yield
    TextColor.reset()

@contextmanager
def cyan():
    TextColor.cyan()
    yield
    TextColor.reset()

@contextmanager
def magenta():
    TextColor.magenta()
    yield
    TextColor.reset()

@contextmanager
def yellow():
    TextColor.yellow()
    yield
    TextColor.reset()

if __name__ == '__main__':
    with green():
        print ("Hello! (green)")
    with red():
        print ("This is red!")
    with blue():
        print ("This is blue!")
    with cyan():
        print ("This is cyan!")
    with magenta():
        print ("This is magenta!")
    with yellow():
        print ("This is yellow!")
    print ("Hello! (uncolored)")
    

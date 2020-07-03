import sys
import atexit
from contextlib import contextmanager
import colorama
from colorama import Fore, Back, Style


class TextColor(object):
    _SETUP=False
    _NoColor=False

    def __init__(self):
        raise Exception("Don't instantiate me.")

    @staticmethod
    def setup(nocolor):
        if TextColor._SETUP:
            return
        TextColor._NoColor=nocolor
        if sys.platform == 'win32':
            colorama.init(strip=True,convert=True,wrap=True)
        else:
            colorama.init()
        atexit.register(TextColor.reset)
        TextColor._SETUP=True

    @staticmethod
    def reset():
        print(Fore.RESET + Back.RESET + Style.RESET_ALL)

    @staticmethod
    def green():
        if not TextColor._NoColor:
            print(Fore.GREEN,end='')

    @staticmethod
    def red():
        if not TextColor._NoColor:
            print(Fore.RED,end='')

    @staticmethod
    def blue():
        if not TextColor._NoColor:
            print(Fore.BLUE,end='')

    @staticmethod
    def cyan():
        if not TextColor._NoColor:
            print(Fore.CYAN,end='')

    @staticmethod
    def magenta():
        if not TextColor._NoColor:
            print(Fore.MAGENTA,end='')

    @staticmethod
    def yellow():
        if not TextColor._NoColor:
            print(Fore.YELLOW,end='')

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


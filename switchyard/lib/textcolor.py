from colorama import init, Fore, Back, Style
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
        init()
        atexit.register(TextColor.reset)
        TextColor.SETUP=True

    @staticmethod
    def reset():
        print(Fore.RESET + Back.RESET + Style.RESET_ALL)

    @staticmethod
    def green():
        print(Fore.GREEN,end='')

    @staticmethod
    def red():
        print(Fore.RED,end='')

    @staticmethod
    def blue():
        print(Fore.BLUE,end='')

    @staticmethod
    def cyan():
        print(Fore.CYAN,end='')

    @staticmethod
    def magenta():
        print(Fore.MAGENTA,end='')

    @staticmethod
    def yellow():
        print(Fore.YELLOW,end='')

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


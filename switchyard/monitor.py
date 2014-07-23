from importlib import import_module
from abc import import ABCMeta,abstractmethod

class AbstractMonitor(metaclass=ABCMeta):
    @abstractmethod
    def __call__(self, devname, now, packet):
        pass

    @abstractmethod
    def stop(self):
        pass

class NullMonitor(AbstractMonitor):
    def __call__(self, devname, now, packet):
        return

    def stop(self):
        pass

class PcapMonitor(AbstractMonitor):
    def __init__(self, outfile):
        pass

    def __call__(self, devname, now, packet):
        pass

    def stop(self):
        pass

class InteractiveMonitor(AbstractMonitor):
    def __call__(self, devname, now, packet):
        pass

class CodeMonitor(AbstractMonitor):
    def __init__(self, module):
        self.__module = module
        if dir(self.__module)

    def __call__(self, devname, now, packet):
        self.__module

    def stop(self):
        pass

if __name__ == '__main__':
    pass

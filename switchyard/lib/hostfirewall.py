from abc import ABCMeta, abstractmethod
import os
import sys

from switchyard.lib.common import log_warn

#
# Rule: 
# 'all'
# proto:port
#

class Firewall(object):
    def __init__(self, interfaces, rules):
        cls = _osmap.get(sys.platform, None)
        if cls is None:
            raise Exception("{} can't run on {}".format(self.__class__.__name__, sys.platform))
        self._firewall_delegate = cls(interfaces, rules)

    def __enter__(self):
        self._firewall_delegate.block()
        return None

    def __exit__(self, exctype, excvalue, traceback):
        self._firewall_delegate.unblock()
        return None


class AbstractFirewall(metaclass=ABCMeta):
    def __init__(self, interfaces, rules):
        pass

    @abstractmethod
    def block(self):
        pass

    @abstractmethod
    def unblock(self):
        pass

class LinuxFirewall(AbstractFirewall):
    def __init__(self, interfaces, rules):
        super().__init__(interfaces, rules)

    def block(self):
        pass
        '''
        iptables-save -> dumps all rules
        iptables-restore

        router.cmdPrint('ebtables -t nat -F')
        router.cmdPrint('ebtables -t nat -P PREROUTING DROP')
        router.cmdPrint('ebtables -F')
        router.cmdPrint('ebtables -P INPUT DROP')
        router.cmdPrint('iptables -F')
        router.cmdPrint('iptables -P INPUT DROP')
        router.cmdPrint('sysctl -w net.ipv4.conf.all.arp_ignore=8') -- set to 0 initially
        '''

    def unblock(self):
        pass


class MacOSFirewall(AbstractFirewall):
    def __init__(self, interfaces, rules):
        print ("Init: {} {}".format(interfaces, rules))
        super().__init__(interfaces, rules)

    def block(self):
        '''
        '''
        print ("Block!")

    def unblock(self):
        '''
        '''
        print ("Unblock!")


_osmap = {
    'darwin': MacOSFirewall,
    'linux': LinuxFirewall
}

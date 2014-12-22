from abc import ABCMeta, abstractmethod
import os
import sys
import re
from subprocess import getstatusoutput, Popen, PIPE, STDOUT

from switchyard.lib.common import log_warn, log_info, log_debug

#
# Rule: 
# 'all'
# proto[:port], e.g., tcp:80, icmp:*, udp:*, icmp, udp
#

def _sendcmd(progargs, cmdlist):
    pipe = Popen(progargs, stdin=PIPE, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
    for cmd in cmdlist:
        print(cmd, file=pipe.stdin)
    pipe.stdin.close()
    output = pipe.stdout.read()
    pipe.stdout.close()
    st = pipe.wait()
    return st,output

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
        self._rules = []

    @abstractmethod
    def block(self):
        pass

    @abstractmethod
    def unblock(self):
        pass

class LinuxFirewall(AbstractFirewall):
    def __init__(self, interfaces, rules):
        super().__init__(interfaces, rules)
        self._intf = interfaces
        st,output = getstatusoutput("iptables-save")
        self._saved_iptables = output
        self._arpignore = {}
        self._rulecmds = [ 'iptables -F', 'iptables -t raw -F' ]

        # --protocol {}  -i {} --port {}
        for intf in interfaces:

            st,output = getstatusoutput('sysctl net.ipv4.conf.{}.arp_ignore'.format(intf))
            self._arpignore[intf] = int(output)
            st,output = getstatusoutput('sysctl -w net.ipv4.conf.{}.arp_ignore=8'.format(intf))

        for r in rules:
            mobj = re.match('(tcp|udp|icmp):(\d+|\*)', r)
            if mobj:
                for intf in interfaces:
                    proto,port = mobj.groups()[:2]
                    self._rulecmds.append('iptables -t raw -P PREROUTING DROP --protocol {} -i {} --port {}'.format(proto, intf, port))
            elif r == 'all':
                self._rulecmds.append('iptables -t raw -P PREROUTING DROP')

        log_debug("Rules to install: {}".format(self._rulecmds))

    def block(self):
        log_info("Saving iptables state and installing switchyard rules")
        for cmd in self._rulecmds:
            st,output = getstatusoutput(cmd)

    def unblock(self):
        # clear switchyard tables, load up saved state
        log_info("Restoring saved iptables state")
        st,output = getstatusoutput("iptables -F")
        st,output = getstatusoutput("iptables -t raw -F")
        st,output = _sendcmd(["iptables-restore"], self._saved_iptables)
        for intf in self._intf:
            st,output = getstatusoutput('sysctl -w net.ipv4.conf.{}.arp_ignore={}'.format(intf, self._arpignore[intf]))

class MacOSFirewall(AbstractFirewall):
    def __init__(self, interfaces, rules):
        super().__init__(interfaces, rules)
        for intf in interfaces:
            for r in rules:
                mobj = re.match('(tcp|udp|icmp):(\d+|\*)', r)
                if mobj:
                    proto,port = mobj.groups()[:2]
                    if port == '*':
                        self._rules.append('block drop on {0} proto {1} from any to any'.format(intf, proto))
                    else:
                        self._rules.append('block drop on {0} proto {1} from any port {2} to any port {2}'.format(intf, proto, port))
                elif r == 'all':
                    self._rules.append('block drop on {} all'.format(intf))
                else:
                    raise Exception("Can't interpret firewall rule {}".format(r))

        st,output = getstatusoutput("pfctl -E")
        mobj = re.search("Token\s*:\s*(\d+)", output, re.M)
        self._token = mobj.groups()[0]
        log_debug("Rules to install: {}".format(self._rules))
        log_info("Enabling pf: {}".format(output.replace('\n', '; ')))

    def block(self):
        '''
        pfctl -a switchyard -f- < rules.txt
        pfctl -a switchyard -F rules
        pfctl -t switchyard -F r
        '''
        st,output = _sendcmd(["/sbin/pfctl","-aswitchyard", "-f-"], self._rules)
        log_debug("Installing rules: {}".format(output))

    def unblock(self):
        '''
        '''
        st,output = getstatusoutput("pfctl -a switchyard -Fr") # flush rules
        log_debug("Flushing rules: {}".format(output))
        st,output = getstatusoutput("pfctl -X {}".format(self._token))
        log_info("Releasing pf: {}".format(output.replace('\n', '; ')))

_osmap = {
    'darwin': MacOSFirewall,
    'linux': LinuxFirewall
}

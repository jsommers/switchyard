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
    try:
        pipe.stdin.close()
    except:
        pass
    output = pipe.stdout.read()
    pipe.stdout.close()
    st = pipe.wait()
    return st,output

class Firewall(object):
    _instance = None
    def __init__(self, interfaces, rules):
        if Firewall._instance:
            raise Exception("Firewall can only be instantiated once.")
        Firewall._instance = self
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

    @staticmethod
    def add_rule(rule):
        Firewall._instance._firewall_delegate.add_rule(rule)


class AbstractFirewall(metaclass=ABCMeta):
    def __init__(self, interfaces, rules):
        self._rules = []

    @abstractmethod
    def block(self):
        pass

    @abstractmethod
    def unblock(self):
        pass

    @abstractmethod
    def add_rule(self, rule):
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
        doall = False
        for r in rules:
            cmds = self._parse_rule(r)
            self._rulecmds.extend(cmds)
            if r == 'all':
                doall = True

        if doall:
            badintf = []
            for intf in interfaces:
                st,output = getstatusoutput('sysctl net.ipv4.conf.{}.arp_ignore'.format(intf))
                if st != 0:
                    badintf.append(intf)
                    continue
                self._arpignore[intf] = int(output.split()[-1])
                st,output = getstatusoutput('sysctl -w net.ipv4.conf.{}.arp_ignore=8'.format(intf))
            for intf in badintf:
                self._intf.remove(intf) # alias of interfaces, so just remove
                                        # from self._intf
        log_debug("Rules to install: {}".format(self._rulecmds))

    def _parse_rule(self, rule):
        cmds = []
        mobj = re.match('(tcp|udp|icmp):(\d+|\*)', rule)
        if mobj:
            for intf in interfaces:
                proto,port = mobj.groups()[:2]
                cmds.append('iptables -t raw -P PREROUTING DROP --protocol {} -i {} --port {}'.format(proto, intf, port))
        elif rule == 'all':
            cmds.append('iptables -t raw -P PREROUTING DROP')
        else:
            raise Exception("Can't parse rule: {}".format(rule))
        return cmds

    def add_rule(self, rule):
        for cmd in self._parse_rule(rule):
            st,output = getstatusoutput(cmd)
            self._rulecmds.append(cmd)
            log_debug("Adding firewall rule: {}".format(cmd))

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
        self._interfaces = interfaces
        for r in rules:
            cmds = self._parse_rule(r)
            self._rules.extend(cmds)

        st,output = getstatusoutput("pfctl -E")
        mobj = re.search("Token\s*:\s*(\d+)", output, re.M)
        if mobj is None:
            raise RuntimeError("Couldn't get pfctl token.  Are you running as root?")
        self._token = mobj.groups()[0]
        log_debug("Rules to install: {}".format(self._rules))
        log_info("Enabling pf: {}".format(output.replace('\n', '; ')))

    def _parse_rule(self, rule):
        for intf in self._interfaces:
            cmds = []
            mobj = re.match('(tcp|udp|icmp):(\d+|\*)', rule)
            if mobj:
                proto,port = mobj.groups()[:2]
                if port == '*':
                    cmds.append('block drop on {0} proto {1} from any to any'.format(intf, proto))
                else:
                    cmds.append('block drop on {0} proto {1} from any port {2} to any port {2}'.format(intf, proto, port))
            elif rule == 'all':
                cmds.append('block drop on {} all'.format(intf))
            else:
                raise Exception("Can't interpret firewall rule {}".format(rule))
        return cmds

    def add_rule(self, rule):
        cmds = self._parse_rule(rule)
        self._rules.extend(cmds)
        st,output = _sendcmd(["/sbin/pfctl","-aswitchyard", "-f-"], cmds)
        log_debug("Adding firewall rules: {}".format(cmds))

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

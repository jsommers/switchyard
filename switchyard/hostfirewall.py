from abc import ABCMeta, abstractmethod
import os
import sys
import re
from subprocess import Popen, STDOUT, PIPE
from copy import deepcopy

from .lib.logging import log_warn, log_info, log_debug
from .outputfmt import VerboseOutput

#
# Rule syntax: 
# 'all'
# proto[:port], e.g., tcp:80, icmp:*, udp:*, icmp, udp
#

def _runcmd(progargs, stdinput=None):
    '''
    Run the command progargs with optional input to be fed in to stdin.
    '''
    stdin = None
    if stdinput is not None:
        assert(isinstance(stdinput, list))
        stdin=PIPE

    err = 0
    output = b''
    log_debug("Calling {} with input {}".format(' '.join(progargs), stdinput))
    try:
        p = Popen(progargs, shell=True, stdin=stdin, 
            stderr=STDOUT, stdout=PIPE, universal_newlines=True)
        if stdinput is not None:
            for cmd in stdinput:
                print(cmd, file=p.stdin)
            p.stdin.close()
        output = p.stdout.read()
        p.stdout.close()
        err = p.wait(timeout=1.0)
    except OSError as e:
        err = e.errno
        log_warn("Error calling {}: {}".format(progargs, e.stderror))
    except Exception as e:
        errstr = str(e)
        log_warn("Error calling {}: {}".format(progargs, errstr))
        err = -1
    log_debug("Result of command (errcode {}): {}".format(err, output))
    return err,output


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
        if VerboseOutput.enabled():
            self._firewall_delegate.show_rules()
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

    @staticmethod
    def _interp_rule(rule):
        mobj = re.match('(?P<proto>tcp|udp|icmp)(:(?P<port>\d+|\*))?', rule)
        if mobj is None:
            raise ValueError("Can't parse rule: {}".format(rule))

        d = mobj.groupdict()
        proto = d['proto']
        port = d['port']
        if port == '*':
            port = None
        return proto,port

    @abstractmethod
    def block(self):
        pass

    @abstractmethod
    def unblock(self):
        pass

    @abstractmethod
    def add_rule(self, rule):
        pass

    @abstractmethod
    def show_rules(self):
        pass


class TestModeFirewall(AbstractFirewall):
    def __init__(self, interfaces, rules):
        super().__init__(interfaces, rules)
        for r in rules:
            self.add_rule(r)

    def block(self):
        pass

    def unblock(self):
        pass

    def show_rules(self):
        pass

    def add_rule(self, rule):
        if rule.strip() == 'all':
            proto,port = 'all',None
        elif rule.strip() == 'none':
            proto,port = 'none',None
        else:
            proto,port = self._interp_rule(rule)
        self._rules.append((proto,port))


class LinuxFirewall(AbstractFirewall):
    def __init__(self, interfaces, rules):
        super().__init__(interfaces, rules)
        self._intf = deepcopy(list(interfaces))
        st,output = _runcmd("/sbin/iptables-save")
        self._saved_iptables = output
        self._arpignore = {}
        self._rulecmds = [ '/sbin/iptables -F', '/sbin/iptables -t raw -F' ]

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
                st,output = _runcmd('/sbin/sysctl net.ipv4.conf.{}.arp_ignore'.format(intf))
                if st != 0:
                    badintf.append(intf)
                    continue
                self._arpignore[intf] = int(output.split()[-1])
                st,output = _runcmd('/sbin/sysctl -w net.ipv4.conf.{}.arp_ignore=8'.format(intf))
            for intf in badintf:
                self._intf.remove(intf) # alias of interfaces, so just remove
                                        # from self._intf
        log_debug("Commands for firewall: {}".format(self._rulecmds))

    def _parse_rule(self, rule):
        cmds = []
        if rule.strip() == 'none':
            pass
        elif rule.strip() == 'all':
            for intf in self._intf:
                cmds.append('/sbin/iptables -t raw -A PREROUTING -j DROP -i {}'.format(intf)) 
        else:    
            proto,port = self._interp_rule(rule)
            if port is not None:
                portpart = " --dport {}".format(port)
            else:
                portpart = ""            

            for intf in self._intf:
                cmds.append('/sbin/iptables -t raw -A PREROUTING -j DROP --protocol {} -i {}{}'.format(
                    proto, intf, portpart))
        return cmds

    def add_rule(self, rule):
        for cmd in self._parse_rule(rule):
            st,output = _runcmd(cmd)
            self._rulecmds.append(cmd)
            log_debug("Adding firewall rule: {}".format(cmd))

    def block(self):
        log_info("Saving iptables state and installing switchyard rules")
        for cmd in self._rulecmds:
            st,output = _runcmd(cmd)

    def unblock(self):
        # clear switchyard tables, load up saved state
        log_info("Restoring saved iptables state")
        st,output = _runcmd("/sbin/iptables -F")
        st,output = _runcmd("/sbin/iptables -t raw -F")
        st,output = _runcmd("/sbin/iptables-restore", [self._saved_iptables])
        for intf in self._intf:
            if intf in self._arpignore:
                st,output = _runcmd('/sbin/sysctl -w net.ipv4.conf.{}.arp_ignore={}'.format(intf, self._arpignore[intf]))

    def show_rules(self):
        st,output = _runcmd("/sbin/iptables -t raw -n --list")
        output = output.strip()
        log_info("Rules installed: {}".format(output)) 


class MacOSFirewall(AbstractFirewall):
    def __init__(self, interfaces, rules):
        super().__init__(interfaces, rules)
        self._interfaces = interfaces
        for r in rules:
            cmds = self._parse_rule(r)
            self._rules.extend(cmds)

        st,output = _runcmd("/sbin/pfctl -E")
        mobj = re.search("Token\s*:\s*(\d+)", output, re.M)
        if mobj is None:
            raise RuntimeError("Couldn't get pfctl token.  Are you running as root?")
        self._token = mobj.groups()[0]
        log_debug("Rules to install: {}".format(self._rules))
        log_info("Enabling pf: {}".format(output.replace('\n', '; ')))

    def _parse_rule(self, rule):
        cmds = []
        if rule.strip() == 'none':
            pass
        elif rule.strip() == 'all':
            rulestr = 'block drop on {} all'
        else:
            proto, port = self._interp_rule(rule)
            if port is not None:
                portpart = " port {}".format(port)
            else:
                portpart = ""
            rulestr = "proto {0} from any{1} to any{1}".format(proto, portpart)
            rulestr = "block drop on {} " + rulestr
        for intf in self._interfaces:
            cmds.append(rulestr.format(intf))
        return cmds

    def add_rule(self, rule):
        cmds = self._parse_rule(rule)
        self._rules.extend(cmds)
        st,output = _runcmd("/sbin/pfctl -aswitchyard -f -", cmds)
        log_debug("Adding firewall rules: {}".format(cmds))

    def block(self):
        '''
        pfctl -a switchyard -f- < rules.txt
        pfctl -a switchyard -F rules
        pfctl -t switchyard -F r
        '''
        st,output = _runcmd("/sbin/pfctl -aswitchyard -f -", self._rules)
        log_debug("Installing rules: {}".format(output))

    def unblock(self):
        '''
        '''
        st,output = _runcmd("/sbin/pfctl -aswitchyard -Fr") # flush rules
        log_debug("Flushing rules: {}".format(output))
        st,output = _runcmd("/sbin/pfctl -X {}".format(self._token))
        log_info("Releasing pf: {}".format(output.replace('\n', '; ')))

    def show_rules(self):
        st,output = _runcmd("/sbin/pfctl -aswitchyard  -srules")
        output = output.replace('No ALTQ support in kernel', '')
        output = output.replace('ALTQ related functions disabled', '')
        output = output.strip()
        log_info("Rules installed: {}".format(output)) 

_osmap = {
    'darwin': MacOSFirewall,
    'linux': LinuxFirewall,
    'test': TestModeFirewall,
}

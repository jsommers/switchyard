import sys
import os
from threading import Thread, Barrier
from textwrap import indent

from switchyard.textcolor import *
from switchyard.hostfirewall import Firewall
from switchyard.llnettest import main_test
from switchyard.llnetreal import main_real, LLNetReal
from switchyard.importcode import import_or_die
from switchyard.lib.socket.socketemu import ApplicationLayer
from switchyard.lib.logging import *
from switchyard.lib.testing import PacketFormatter
from switchyard.lib.topo import Topology
from switchyard.sim.cli import run_simulation
from switchyard.lib.interface import make_device_list

_setup_ok = False
_netobj = None

def start_framework(args):
    global _netobj, _setup_ok

    # assume testmode if compile flag is set
    args.testmode = False
    if args.compile or args.tests:
        args.testmode = True

    if args.verbose:
        PacketFormatter.full_display(True)

    if args.cli:
        t = Topology()
        if args.topology:
            try:
                t = load_from_file(args.topology)
            except FileNotFoundError:
                print ("No such file {} exists to load topology.".format(args.topology))
                return
        run_simulation(t)
        return

    if args.usercode is None and not args.compile:
        log_failure("You need to specify the name of your module to run "
                    "as the last argument")
        return

    waiters = 1 
    if args.app:
        waiters += 1 
    barrier = Barrier(waiters)

    if args.app:
        ApplicationLayer._init()
        _appt = Thread(target=_start_app, args=(args.app,barrier))
        _appt.start()

    if args.testmode:
        if args.usercode and args.compile:
            log_info("You specified user code to run with compile flag, "
                     "but I'm just doing compile.")
        setattr(sys, "platform", "test")
        with Firewall([], args.fwconfig):
            _setup_ok = True
            barrier.wait() 
            main_test(args.usercode, args.tests, args)
    else:
        if sys.platform != 'win32' and os.geteuid() != 0:
            log_warn("You're running in real mode, but not as root.  "
                "You should expect errors, but I'm going to "
                "continue anyway.")
        if args.exclude is None:
            args.exclude = []
        if args.intf is None:
            args.intf = []

        if args.app:
            args.fwconfig = []
        elif args.fwconfig is None:
            args.fwconfig = ('all',)

        devlist = make_device_list(includes=args.intf, excludes=args.exclude)
        if not devlist:
            log_failure("There are no network interfaces I can use after "
                        "processing include/exclude lists")
            alldevs = make_device_list([], [])
            log_failure("Here are all the interfaces I see on your system: "
                        "{}".format(', '.join(list(alldevs))))
            barrier.wait()
            return

        with Firewall(devlist, args.fwconfig):
            _setup_ok = True
            barrier.wait()
            _netobj = LLNetReal(devlist)
            main_real(args.usercode, _netobj, args)


def _start_app(appcode, firewall_setup):
    # don't start app-layer code until the lower layers are initialized
    firewall_setup.wait()
    # and beware that something may have failed, so only start app code
    # if it looks like everything was initialized correctly
    if _setup_ok:
        try:
            import_or_die(appcode, [])
        except Exception as e:
            import traceback
            with red():
                print('*'*60)
                print ("Exception while running your code: {}".format(e))
                lines = indent(traceback.format_exc(), '   ').split('\n')
                doprint = False
                for line in lines:
                    if doprint:
                        print (line)
                    elif appcode in line:
                        print (line)
                        doprint = True
                print ('*'*60)

    if _netobj is not None:
        _netobj.shutdown()

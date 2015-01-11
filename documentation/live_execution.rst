.. _runlive:

Running in a "live" environment
*******************************

Switchyard can run in any live environment that supports the libpcap packet capture library.  In particular, you can run your Switchyard code on a standard Linux host, on a MacOS X host, or within a Linux-based virtual machine, including Mininet virtual nodes.

Running on a standard host
==========================


The basic recipe for running Switchyard on a live host is pretty simple.  If we wanted to run a Switchyard program and use *all* available network interfaces on the system, we could use the following::

    $ srpy.py myhub.py

Note that you'll need to run Switchyard as root since it uses libpcap for sending and receiving packets, and you need root privileges to access live interfaces with libpcap.  If you're using a Python virtualenv to manage the various module dependencies for Switchyard, you may not be able directly just type ``sudo srpy.py myhub.py`` to run as root, since you won't have properly sourced the virtualenv settings when you run ``srpy.py`` as root.  To resolve this issue, you can either:
 
 * Just do ``sudo -s`` to get a root shell, and go to it.  For the same reasons why you shouldn't just run everything as root, this is not the preferred approach.

 * Alternatively (and preferably), you can create a shell script which sources the virtualenv, then runs ``srpy.py``.  For example, if your virtualenv is called ``pyenv`` and is located in the same directory as the top-level directory of Switchyard, the script could just be::

    #!/bin/bash

    . ./pyenv/bin/activate
    python3 ./srpy.py $*


Note also that Switchyard will automatically install host firewall rules so that the host is *prevented* from responding to packets since it is assumed that you want Switchyard to handle all packets.  If that's not the case, you can specify that certain interfaces should be included or excluded from Switchyard's control.  You can use the ``-i`` option to say that only certain interfaces should be included, or the ``-e`` option to exclude certain interfaces.

For example, if we want to just use the interface named ``eth0``, we could invoke ``srpy`` as follows (note that we're using the shell script approach taken above)::

    $ sudo ./srpy.sh -i eth0 myhub.py

Just as with running Switchyard in a test environment, you may wish to use the ``-v`` and/or ``-d`` options to increase Switchyard's output verbosity or to include debugging messages, respectively.

Last note: there are no real differences with running Switchyard on a "real" host compared with running in Mininet or a virtual host.  In a virtual environment it may be more likely that you want to use all interfaces with Switchyard, thus the ``-i`` and ``-e`` options may be less relevant.  Also, when you open xterm's within Mininet you'll already have a root shell so there's no need to use ``sudo`` to invoke Switchyard.


Release notes
*************

The headings below refer either to branches on Switchyard's github repo (v1 and v2) or tags (2017.01.1).

2017.01.4
---------
More bugfixes.

2017.01.3
---------
Minor bugfixes.

2017.01.2
---------

Add the capability to pass arguments to a Switchyard program via ``-g`` option to ``swyard``.
Switchyard parses and assembles ``*args`` and ``**kwargs`` to pass into the user code, being careful to only pass them if the code can accept them.

2017.01.1
---------

Major revision; expansion of types of exercises supported (notably application-layer programs via socket emulation) and several non-backward compatible API changes.  Simplified user code import (single import of switchyard.lib.userlib).  Installation via standard setuptools, so easily installed via easy_install or pip.  Major revision of documentation.  Lots of new tests were written, bringing test coverage above 90%.  Expansion of exercises is still in progress.

Some key API changes to be aware of:

 * the Scenario class is renamed TestScenario.  The PacketOutputEvent previously allowed Openflow 1.0-like wildcard strings to specify wildcards for matching packets; these strings are no longer supported.  To specify wildcards, a tuple of (classname,attribute) must be used; refer to :ref:`test-scenario-creation`, above.
 * ``recv_packet`` *always* returns a timestamp now; it returns a 3-tuple (named tuple) of timestamp, input_port and packet.
 * The only import required by user code is switchyard.lib.userlib, although individual imports are still fine (just more verbose).
 * Instead of invoking ``srpy.py``, a ``swyard`` program is installed during the new install process.  ``swyard`` has a few command-line changes compared with ``srpy.py``.  In particular, the ``-s`` option has gone away; to run Switchyard with a test, just use the ``-t`` option with the scenario file as the argument.


v2
--

Complete rewrite of v1.  Moved to Python 3 and created packet parsing libraries, new libpcap interface library (pcapffi).  Redesigned test scenario modules and an expanded of publicly available exercises.  Used at Colgate twice and University of Wisconsin-Madison twice.  Available on the ``v2`` branch on github.

v1
--

First version, which used the POX packet parsing libraries and had a variety of limitations.  Implemented in Python 2 and used at Colgate once.  Available on the ``v1`` branch on github, but very much obsolete.

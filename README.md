Switchyard
==========

Switchyard (or "switchy") is a low-level networking library for software switches/routers in Python (version 2).  Intended for use in layer2-/layer3-oriented labs and projects in computer networking courses.

There is some [documentation](https://github.com/jsommers/switchyard/wiki) in the Github wiki for Switchyard, though note that it is a work in progress.

Switchyard currently makes use of the [POX Openflow controller](https://github.com/noxrepo/pox) platform for packet parsing libraries, and other functions.  

Switchyard can run in a standalone test mode, or also nicely within Mininet.  The [Mininet project](http://www.mininet.org) pages have documentation for Mininet, as well as lots of other good stuff.

Note that development on this version of Switchyard is basically done; work has shifted to version 2 (v2 branch), which requires Python 3 but has very few external dependencies.

----

I gratefully acknowledge support from the NSF.  The materials here are
based upon work supported by the National Science Foundation under
grant CNS-1054985 ("CAREER: Expanding the functionality of Internet
routers").

Any opinions, findings, and conclusions or recommendations expressed
in this material are those of the author and do not necessarily
reflect the views of the National Science Foundation.

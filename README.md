Switchyard
==========

Switchyard (or "switchy") is a low-level networking library for software switches/routers in Python.  Intended for use in layer2-/layer3-oriented labs and projects in computer networking courses.

Documentation is available at http://cs.colgate.edu/~jsommers/switchyard
Documentation is written using the Python Sphinx package; doc sources are
available in the documentation directory.  

Switchyard can run in a standalone test mode, in a simulation environment with a nice little command-line interface, or also within a Linux host and or in Mininet.  This version of Switchyard is a complete overhaul of the original framework written in late 2013, and many parts of the code are under active development.  For the older version of Switchyard, see the v1 branch.  Importantly, this version of Switchyard requires Python 3.4.

Installation
------------

Switchyard requires a few additional Python libraries, all identified in requirements.txt.  You can either install directly to your system Python directories, or use a virtualenv (see https://docs.python.org/3/library/venv.html).  

To install into your system Python directories, the easiest method is to use pip (or pip3 --- make sure you're using the Python 3-version of pip):

    $ pip install -r requirements.txt

On Ubuntu and Fedora systems, you'll also likely need to install additional packages (do this before using pip to install the Python libraries).  The list of libraries below is for recent versions of Ubuntu (14.04 and later) and Fedora (20 and later):

 * Ubuntu: `sudo apt-get install libffi-dev libpcap-dev python3-dev`
 * Fedora: `sudo yum install libffi-devel libpcap-devel python3-devel`

If pip3 is not installed, you'll also need to install that (on Ubuntu: `sudo apt-get install python3-pip`.)

Documentation and Exercises
---------------------------
 
 * Documentation sources can be found in the documentation directory.  See
   http://cs.colgate.edu/~jsommers/switchyard for compiled/built docs.

 * Sample exercises (in ReStructuredText format) can be found in the
   examples/exercises directory.  

 * Instructor-only materials such as test scenarios and other scripts
   available on request to the author of Switchyard (jsommers@colgate.edu).

Credits
-------

I gratefully acknowledge support from the NSF.  The materials here are
based upon work supported by the National Science Foundation under
grant CNS-1054985 ("CAREER: Expanding the functionality of Internet
routers").

Any opinions, findings, and conclusions or recommendations expressed
in this material are those of the author and do not necessarily
reflect the views of the National Science Foundation.

License
-------

This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License. 
http://creativecommons.org/licenses/by-nc-sa/4.0/

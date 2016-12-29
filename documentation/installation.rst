.. _install:

Installing Switchyard
*********************

Switchyard has been tested and developed on the following operating systems:

 * macOS 10.10 and later
 * Ubuntu LTS releases from 14.04 and later
 * Fedora 21

Note that these are all Unix-based systems.  Switchyard may be enhanced in the future to support Windows-based systems.  Ubuntu (current LTS) and macOS receive the most testing of Unix-based operating systems.

---

The steps for getting Switchyard up and running are as follows:

  0. Install Python 3.4 or later, if you don't already have it.
  1. Install any necessary libraries for your operating system.
  2. Create an Python "virtual environment" for installing Python modules (or install the modules to your system Python)
  3. Install Switchyard.

For step 0, you're on your own.  Go to https://www.python.org/downloads/, or install packages via your OS'es package system, or use homebrew if you're on a Mac.  Have fun.

The specific libraries necessary for different OSes (step 1) are described below, but steps 2 and 3 are the same for all operating systems and are covered next.  

The recommended install procedure is to create a Python virtual environment for installing Switchyard and other required Python modules.  One way to create a new virtual environment is to execute the following at a command line (in the folder in which you want to create the virtual environment)::

    $ python3 -m venv syenv

This command will create a new virtual environment called ``syenv``.  Once that's done, you can "activate" that environment and install Switchyard as follows::

    $ source ./syenv/bin/activate
    (syenv)$ python3 -m pip install switchyard

That's it.  Once you've done that, the ``swyard`` program should be on your ``PATH`` (you can check by typing ``which swyard``).  If you no longer want to use the Python virtual environment you've created, you can just type ``deactivate``.  

Operating system-specific instructions
======================================

MacOS X
-------

The easiest way to get Switchyard running in macOS is to install homebrew.  You can use ``brew`` to install Python 3.  You should also ``brew`` to install the ``libpcap`` package.  That should be all that is necessary.

Ubuntu
------

For Ubuntu systems, you'll need to use ``apt-get`` or something similar to install the following packages::

    libffi-dev libpcap-dev python3-dev python3-pip python3-venv

Fedora/RedHat
-------------

For Fedora and RedHat-based systems, you'll need to use ``yum`` or something similar to install a similar set of packages as with Ubuntu (but with the right name changes for the way packages are identified on Fedora)::

    libffi-devel libpcap-devel python3-devel python3-pip python3-virtualenv


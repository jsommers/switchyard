.. _install:

Installing Switchyard
*********************

Switchyard has been tested and developed on the following operating systems:

 * MacOS X 10.10
 * Ubuntu 14.04
 * Fedora 21

Note that these are all Unix-based systems.  Switchyard may be enhanced in the future to support Windows-based systems, but there no plans currently to do so.

---

The steps for getting Switchyard up and running are as follows:

  0. Install Python 3.4 or later, if you don't already have it.
  1. Install any necessary libraries and/or programs on your OS
  2. Create an Python "virtual environment" for installing Python modules (or install the modules to your system Python)
  3. Install the necessary Python modules

For step 0, you're on your own.  Go to https://www.python.org/downloads/, or install packages via
your OS'es package system, or use homebrew if you're on a Mac.  Have fun.

The specific libraries necessary for different OSes (step 1) are described below, but steps 2 and 3 are the same for all operating systems and are covered next.  See below for how to install libraries on specific OSes.

I recommend creating a Python virtual environment for installing the Switchyard-specific modules.  Python 3 includes the program ``pyvenv`` for this purpose.  You can invoke it with the name of the environment you're creating::

    $ pyvenv swenv

This command will create a new virtual environment called ``swenv``.  Once that's done, you can "load" that environment and install the necessary Python modules. Let's say that we're starting from scratch and we don't even have the sourcecode for Switchyard.  Here are the steps::

    $ . ./swenv/bin/activate
    (swenv)$ git clone https://github.com/jsommers/switchyard
    ... git clone happens
    (swenv)$ cd switchyard
    (swenv)$ pip install -r requirements.txt

Some (experimental) parts of Switchyard use the ``matplotlib`` Python libraries.  These can be difficult to compile on some systems, but if you want to use them you can try running ``pip install matplotlib``.  Your mileage may greatly vary.


Operating system-specific instructions
======================================

MacOS X
-------

The easiest way to get Switchyard running in MacOS X is to install homebrew.  You can use ``brew`` to install Python 3.  You should also ``brew`` to install the ``libpcap`` package.  That should be all that is necessary.

Fedora/RedHat
-------------

For Fedora and RedHat-based systems, you'll need to use ``yum`` or something similar to install the following packages::

    libffi-devel libpcap-devel freetype-devel python3-devel gcc make git

Ubuntu
------

For Ubuntu systems, you'll need similar packages as those required on Fedora (but with the right name changes for the way packages are identified on Ubuntu)::

    python3-venv gcc git make python3-dev libpcap-dev libffi-dev freetype-dev

Note that the main difference is that Ubuntu doesn't include the ``pyvenv`` tool by default in its base Python 3 installation.

Sample Exercises
****************

This folder contains sources for sample exercises.  Each subfolder includes 
a project description and various support files.  Note: if you're viewing this source through Github, it will render individual ``.rst`` files if you click on them.  If you don't like ReStructuredText, use pandoc to convert to a format you like better.

**Instructors**: if you'd like the Switchyard test files (and test source code), please email me.  Any tests referred to in the project/exercise descriptions are intentionally excluded from this repo (except for the firewall, currently).

An overview of existing and in-the-works exercises is as follows:

Learning switch
	Build a simple Ethernet learning switch.  This is a nice starter exercise for getting accustomed to the APIs and workflow in Switchyard.  Some extensions and variants to this exercise are included in the description, such as a spanning-tree protocol-like capability.

IP router
	This is really a set of 3 projects designed to gradually built up capabilities to implement an IPv4 router that uses a static forwarding table.  Descriptions of extensions and variants such as dynamic routing are included.

Firewall
	In this exercise, build a stand-alone firewall device with token bucket rate-limiting capability.

UDP network stack + application
	This exercise is an introduction to using Switchyard's socket API emulation capabilities.  The goal is to build the Ethernet/IP/UDP layers to support a UDP-based application, along with a basic windowed form of transport reliability.

License
-------

This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
http://creativecommons.org/licenses/by-nc-sa/4.0/

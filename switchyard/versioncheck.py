from __future__ import print_function
import sys

# version test, for sanity
if sys.version_info.major < 3 or sys.version_info.minor < 4:
    print("Switchyard requires Python 3.4")
    sys.exit(-1)

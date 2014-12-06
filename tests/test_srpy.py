import unittest 

from switchyard.lib.testing import *

class TestHarnestTests(unittest.TestCase):
    def setUp(self):
        pass

# test srpy calls like interface_by_ipaddr
# interface_by_name interface_by_macaddr; if the port_ calls are made,
# both actually get called; that will improve test coverage
# in switchyard.lib.common

# 

if __name__ == '__main__':
    unittest.main()
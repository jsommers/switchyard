from switchyard.lib.textcolor import green, red, blue, cyan, magenta, yellow
import unittest 

class ColorlibTests(unittest.TestCase):
    def testContext(self):
        print ("These tests need eyes...")
        with green():
            print ("This should be green!")
        with red():
            print ("This should be red!")
        with blue():
            print ("This should be blue!")
        with cyan():
            print ("This should be cyan!")
        with magenta():
            print ("This should be magenta!")
        with yellow():
            print ("This should be yellow!")
        print ("This should not be colored")


if __name__ == '__main__':
    unittest.main()

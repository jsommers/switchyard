import unittest 
import sys
import os
import tempfile
import switchyard.importcode as imp

class TestImporter(unittest.TestCase):
    def _writeFile(self, name):
        with open(name, "w") as outf:
            print("x = 1", file=outf)
            print("def fn():", file=outf)
            print("    print(x)", file=outf)

    def testImporter1(self):
        name = "testimp1.py"
        self._writeFile(name)
        mod = imp.import_or_die(name, None)
        self.assertIsNone(mod)
        self.assertIn(name[:-3], sys.modules)
        os.unlink(name)

    def testImporter2(self):
        name = "testimp2.py"
        self._writeFile(name)
        xfn = imp.import_or_die(name, ["fn"])
        self.assertIsNotNone(xfn)
        self.assertEqual(xfn.__name__, "fn")
        self.assertIn(name[:-3], sys.modules)
        os.unlink(name)

    def testImporter3(self):
        name = "testimp3.py"
        self._writeFile(name)
        with self.assertRaises(ImportError):
            imp.import_or_die(name, ["ugh"])
        os.unlink(name)

    def testImporter4(self):
        name = "testimp4.py"
        xfile = os.path.join(tempfile.gettempdir(), name)
        self._writeFile(xfile)
        xfn = imp.import_or_die(xfile, ["fn"])
        self.assertIsNotNone(xfn)
        self.assertEqual(xfn.__name__, "fn")
        self.assertIn(name[:-3], sys.modules)
        os.unlink(xfile)

if __name__ == '__main__':
    unittest.main()

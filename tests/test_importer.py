import unittest 
import sys
import os
import tempfile
import importlib

import switchyard.importcode as imp

class TestImporter(unittest.TestCase):
    def _writeFile(self, name):
        with open(name, "w") as outf:
            print("x = 1", file=outf)
            print("def fn():", file=outf)
            print("    print(x)", file=outf)

    def setUp(self):
        importlib.invalidate_caches()

    def testImporter1(self):
        name = "firsttest.py"
        self._writeFile(name)
        mod = imp.import_or_die(name, None)
        self.assertIsNone(mod)
        self.assertIn(name[:-3], sys.modules)
        os.unlink(name)

    def testImporter1b(self):
        name = "firsttwo_partdau.py"
        self._writeFile(name)
        mod = imp.import_or_die(name[:-3], None)
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
        xfn = imp.import_or_die(xfile, ["main","blob","fn"])
        self.assertIsNotNone(xfn)
        self.assertEqual(xfn.__name__, "fn")
        self.assertIn(name[:-3], sys.modules)
        os.unlink(xfile)

    def testImporter5(self):
        with self.assertLogs() as cm:
            with self.assertRaises(ImportError):
                imp.import_or_die("/tmp/notafile.py", None)
        self.assertIn("couldn't import module", cm.output[0])
        with self.assertLogs() as cm:
            with self.assertRaises(ImportError):
                imp.import_or_die("nothinghere.py", None)
        self.assertIn("couldn't import module", cm.output[0])
        with self.assertLogs() as cm:
            with self.assertRaises(ImportError):
                imp.import_or_die("nothinghere", None)
        self.assertIn("couldn't import module", cm.output[0])


if __name__ == '__main__':
    unittest.main()

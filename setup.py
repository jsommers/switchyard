from setuptools import setup, find_packages

thisversion = '2017.01.3'

setup(name="switchyard", 
      version=thisversion,
      description="Switchyard is a framework for creating networked systems",
      author="Joel Sommers",
      author_email="jsommers@colgate.edu",
      url="https://github.com/jsommers/switchyard",
      download_url="http://cs.colgate.edu/~jsommers/downloads/switchyard-{}.tar.gz".format(thisversion),
      keywords=['education', 'networked systems',],
      zip_safe=True,
      packages=find_packages(),
      python_requires='>=3.4', 
      package_data={ '': ['*.txt', '*.rst'], },
      exclude_package_data={'': ['README.rst','README.md']},
      install_requires=["cffi >=1.6.0","colorama >=0.3.3","networkx >=1.8.1"],
      tests_require=['coverage >=3.7.1'],
      entry_points= {
        'console_scripts': [ 'swyard = switchyard.swyard:main' ],
      },
      license="This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.  http://creativecommons.org/licenses/by-nc-sa/4.0/",
      classifiers=[
              "Programming Language :: Python :: 3 :: Only",
              "Development Status :: 4 - Beta",
              "Topic :: Scientific/Engineering",
              "Topic :: Education",
              "Topic :: Software Development :: Libraries",
              "Topic :: System :: Networking",
              "Environment :: Console",
              "Intended Audience :: Education",
              "Intended Audience :: Science/Research",
      ],
      long_description='''
Switchyard is a library and framework for creating networked systems in Python.  It is primarily intended for educational use and supports creating devices from layer 2 (Ethernet) all the way through the application layer.

Documentation is available at http://cs.colgate.edu/~jsommers/switchyard
Documentation is written using the Python Sphinx package; doc sources are
available in the documentation directory.
'''
)

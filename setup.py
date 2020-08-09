from setuptools import setup, find_packages

with open('README.md', 'r') as fh:
    LONG_DESCRIPTION = fh.read()

VERSION = '09.08.2020'
PACKAGE_NAME = 'pereader'
AUTHOR = 'Matthew Peart'
URL = 'https://github.com/matthewPeart/PEReader'

LICENSE = 'MIT License'
DESCRIPTION = 'A lightweight Python module for parsing portable executable files.'

INSTALL_REQUIRES = [
]

KEYWORDS = [
    'pe',
    'parser',
    'exe',
    'dll',
    'pereader'
]

CLASSIFIERS = [
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: 3.8',
    'Operating System :: OS Independent'
]

setup(name=PACKAGE_NAME,
      version=VERSION,
      description=DESCRIPTION,
      long_description=LONG_DESCRIPTION,
      long_description_content_type='text/markdown',
      py_modules=['pereader'],
      package_dir={'': 'src'},
      classifiers=CLASSIFIERS,
      keywords =KEYWORDS,
      author=AUTHOR,
      license=LICENSE,
      url=URL,
      install_requires=INSTALL_REQUIRES,
      packages=find_packages()
)

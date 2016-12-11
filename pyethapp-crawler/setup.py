#!/usr/bin/env python
# -*- coding: utf-8 -*-
import codecs
from setuptools import setup
from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):
    def __init__(self, *args, **kwargs):
        TestCommand.__init__(self, *args, **kwargs)
        self.test_suite = True

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.test_args)
        raise SystemExit(errno)


with codecs.open('README.rst', encoding='utf8') as readme_file:
    README = readme_file.read()

with codecs.open('HISTORY.rst', encoding='utf8') as history_file:
    HISTORY = history_file.read().replace('.. :changelog:', '')

LONG_DESCRIPTION = README + '\n\n' + HISTORY

INSTALL_REQUIRES_REPLACEMENTS = {
    'https://github.com/ethereum/ethash/tarball/master#egg=pyethash': 'pyethash',
}

INSTALL_REQUIRES = list()
with open('requirements.txt') as requirements_file:
    for requirement in requirements_file:
        dependency = INSTALL_REQUIRES_REPLACEMENTS.get(
            requirement.strip(),
            requirement.strip(),
        )

        INSTALL_REQUIRES.append(dependency)

INSTALL_REQUIRES = list(set(INSTALL_REQUIRES))

# *IMPORTANT*: Don't manually change the version here. Use the 'bumpversion' utility.
# see: https://github.com/ethereum/pyethapp/wiki/Development:-Versions-and-Releases
version = '1.5.0'

setup(
    name='pyethapp',
    version=version,
    description='Python Ethereum Client',
    long_description=LONG_DESCRIPTION,
    author='HeikoHeiko',
    author_email='heiko@ethdev.com',
    url='https://github.com/ethereum/pyethapp',
    packages=[
        'pyethapp',
    ],
    package_data={
        'pyethapp': ['genesisdata/*.json']
    },
    license='MIT',
    zip_safe=False,
    keywords='pyethapp',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
    cmdclass={'test': PyTest},
    install_requires=INSTALL_REQUIRES,
    tests_require=[
        'ethereum-serpent>=1.8.1',
    ],
    entry_points='''
    [console_scripts]
    pyethapp=pyethapp.app:app
    '''
)

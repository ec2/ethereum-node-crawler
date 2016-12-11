===============================
pyethapp
===============================

.. image:: https://badges.gitter.im/Join%20Chat.svg
   :alt: Join the chat at https://gitter.im/ethereum/pyethapp
   :target: https://gitter.im/ethereum/pyethapp?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge

.. image:: https://img.shields.io/travis/ethereum/pyethapp.svg
        :target: https://travis-ci.org/ethereum/pyethapp

.. image:: https://coveralls.io/repos/ethereum/pyethapp/badge.svg
        :target: https://coveralls.io/r/ethereum/pyethapp


.. image:: https://img.shields.io/pypi/v/pyethapp.svg
        :target: https://pypi.python.org/pypi/pyethapp

.. image:: https://readthedocs.org/projects/pyethapp/badge/?version=latest
        :target: https://readthedocs.org/projects/pyethapp/?badge=latest


Introduction
------------

pyethapp is the python based client implementing the Ethereum_ cryptoeconomic state machine.

Ethereum as a platform is focussed on enabling people to build new ideas using blockchain technology.

The python implementation aims to provide an easily hackable and extendable codebase.

pyethapp leverages two ethereum core components to implement the client:

* pyethereum_ - the core library, featuring the blockchain, the ethereum virtual machine, mining
* pydevp2p_ - the p2p networking library, featuring node discovery for and transport of multiple services over multiplexed and encrypted connections


.. _Ethereum: http://ethereum.org/
.. _pyethereum: https://github.com/ethereum/pyethereum
.. _pydevp2p: https://github.com/ethereum/pydevp2p




Installation
------------

Notes
~~~~~

Pyethapp runs on Python 2.7. If you don't know how to install an
up-to-date version of Python, have a look
`here <https://wiki.python.org/moin/BeginnersGuide>`__. It is always
advised to install system-dependecies with the help of a package manager
(e.g. *homebrew* on Mac OS X or *apt-get* on Debian).

Please install a *virtualenv* environment for a comfortable Pyethapp
installation. Also, it is always recommended to use it in combination
with the
`virtualenvwrapper <http://virtualenvwrapper.readthedocs.org/en/latest/>`__
extension.

The
`Homestead <https://ethereum-homestead.readthedocs.io/en/latest/introduction/the-homestead-release.html>`__-ready
version of Pyethapp is ``v1.2.0``.

Installation on Ubuntu/Debian
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

First install the system-dependecies for a successful build of the
Python packages:

.. code:: shell

    $ apt-get install build-essential automake pkg-config libtool libffi-dev libgmp-dev

Installation of Pyethapp and it's dependent Python packages via
`PyPI <https://pypi.python.org/pypi/pyethapp>`__:

.. code:: shell

    ($ mkvirtualenv pyethapp)
    $ pip install pyethapp

Installation on OS X
~~~~~~~~~~~~~~~~~~~~

(More detailed instructions can be found in the `Mac OS X installation instructions`_)

First install the system-dependecies for a successful build of the
Python packages:

.. code:: shell

    $ brew install automake libtool pkg-config libffi gmp openssl

Installation of Pyethapp and it's dependent Python packages via
`PyPI <https://pypi.python.org/pypi/pyethapp>`__:

.. code:: shell

    ($ mkvirtualenv pyethapp)
    $ pip install pyethapp

.. _`Mac OS X installation instructions`: https://github.com/ethereum/pyethapp/blob/develop/docs/installation_os_x.rst

Development version
~~~~~~~~~~~~~~~~~~~

If you want to install the newest version of the client for development
purposes, you have to clone it directly from GitHub.

First install the system dependencies according to your Operating System
above, then:

.. code:: shell

    ($ mkvirtualenv pyethapp)
    $ git clone https://github.com/ethereum/pyethapp
    $ cd pyethapp
    $ python setup.py develop

This has the advantage that inside of Python's
``lib/python2.7/site-packages`` there is a direct link to your directory
of Pyethapp's source code. Therefore, changes in the code will have
immediate effect on the ``pyethapp`` command in your terminal.

Connecting to the network
-------------------------

If you type in the terminal:

.. code:: shell

    $ pyethapp

will show you all available commands and options of the client.

To get started, type:

.. code:: shell

    ($ workon pyethapp)
    $ pyethapp account new

This creates a new account and generates the private key. The key-file
is locked with the password that you entered and they are stored in the
``/keystore`` directory. You can't unlock the file without the password
and there is no way to recover a lost one. Do **not delete the
key-files**, if you still want to be able to access Ether and Contracts
associated with that account.

To connect to the live Ethereum network, type:

.. code:: shell

    ($ workon pyethapp)
    $ pyethapp run

This establishes the connection to Ethereum's p2p-network and downloads
the whole blockchain on the first invocation.

For additional documentation how to use the client, have a look at the
`Wiki <https://github.com/ethereum/pyethapp/wiki>`__.

Data directory:
~~~~~~~~~~~~~~~

When running the client without specifying a data-directory, the
blockchain-data and the keystore-folder will be saved in a default
directory, depending on your Operating System.

on Mac OS X:


.. code:: shell

      ~/Library/Application\ Support/pyethapp

on Linux:


.. code:: shell

    ~/.config/pyethapp

This folder also holds the ``config.yaml`` file, in which you can modify
your default configuration parameters.

To provide a different data-directory, e.g. for additionally syncing to
the testnet, run the client with the ``-d <dir>`` / ``--data-dir <dir>``
argument.

Available Networks
------------------

* Live (*Frontier* / *Homestead*)
* Test (*Morden*)

Currently there are two official networks available. The "Live Network" is
called *Frontier* (soon to be *Homestead*) and this is what the client will
connect to if you start it without any additional options.

Additionally there is the official test network called Morden_ which can be
used to test new code or otherwise experiment without having to risk real
money.
Use the `--profile` command line option to select the test network:

.. code:: shell

   $ pyethapp --profile testnet run


.. note:: If you've previously connected to the live network you will also need
   to specify a new data directory by using the `--data-dir` option.


.. _Morden: https://github.com/ethereum/wiki/wiki/Morden

Interacting
-----------

You can interact with the client using the JSONRPC api or directly on the console.

* https://github.com/ethereum/pyethapp/wiki/The_Console
* https://github.com/ethereum/pyethapp/blob/master/pyethapp/rpc_client.py

Status
------

* Working PoC9 prototype
* interoperable with the go and cpp clients
* jsonrpc (mostly)

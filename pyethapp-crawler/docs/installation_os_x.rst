Installation on Mac OS X
========================

The following instructions assume a fresh installation of OS X.

#. Install C/C++ compiler infrastructure::

    $ xcode-select --install

   * Click "Install" then "Agree", wait for installation to complete

#. Install `Homebrew`_ (Mac OS X package manager)::

    $ /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

   * Follow the instructions

#. Install system packages needed for `pyethapp` and its dependencies::

    $ brew install automake libtool pkg-config libffi gmp openssl

#. Install `pip`_ (a Python package manager)::

    $ sudo easy_install pip

#. Install `virtualenv`_::

    $ sudo pip install virtualenv

#. Create a virtualenv for pyethapp::

    $ virtualenv pyethapp

#. "Activate" the virtualenv::

    $ source pyethapp/bin/activate

#. Install pyethapp::

    $ pip install pyethapp


.. _Homebrew: http://brew.sh
.. _pip: https://pip.pypa.io/en/stable/
.. _virtualenv: https://virtualenv.pypa.io


The installation should now be complete and you can start pyethapp with the
following command::

    $ pyethapp/bin/pyethapp run

To simplify things you can also symlink pyethapp into a directory on your PATH::

    $ ln -s $(pwd)/pyethapp/bin/pyethapp /usr/local/bin

After that you will be able to start pyethapp simply by typing::

    $ pyethapp run

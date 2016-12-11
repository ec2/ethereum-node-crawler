"""
Essential parts borrowed from https://github.com/ipython/ipython/pull/1654
"""
import cStringIO
import errno
import os
import select
import signal
import sys
import time
from logging import StreamHandler, Formatter

import gevent
from gevent.event import Event
import IPython
import IPython.core.shellapp
from IPython.lib.inputhook import inputhook_manager, stdin_ready
from devp2p.service import BaseService
from ethereum import processblock
from ethereum.exceptions import InvalidTransaction
from ethereum.slogging import getLogger
from ethereum.transactions import Transaction
from ethereum.utils import denoms, normalize_address

from pyethapp.utils import bcolors as bc
from pyethapp.rpc_client import ABIContract

log = getLogger(__name__)  # pylint: disable=invalid-name

ENTER_CONSOLE_TIMEOUT = 3
GUI_GEVENT = 'gevent'


def inputhook_gevent():
    while not stdin_ready():
        gevent.sleep(0.05)
    return 0


@inputhook_manager.register('gevent')
class GeventInputHook(object):

    def __init__(self, manager):
        self.manager = manager

    def enable(self, app=None):
        """Enable event loop integration with gevent.
        Parameters
        ----------
        app : ignored
            Ignored, it's only a placeholder to keep the call signature of all
            gui activation methods consistent, which simplifies the logic of
            supporting magics.
        Notes
        -----
        This methods sets the PyOS_InputHook for gevent, which allows
        gevent greenlets to run in the background while interactively using
        IPython.
        """
        self.manager.set_inputhook(inputhook_gevent)
        self._current_gui = GUI_GEVENT
        return app

    def disable(self):
        """Disable event loop integration with gevent.
        This merely sets PyOS_InputHook to NULL.
        """
        self.manager.clear_inputhook()


# ipython needs to accept "--gui gevent" option
IPython.core.shellapp.InteractiveShellApp.gui.values += ('gevent',)


class SigINTHandler(object):

    def __init__(self, event):
        self.event = event
        self.installed = None
        self.installed_force = None
        self.install_handler()

    def install_handler(self):
        if self.installed_force:
            self.installed_force.cancel()
            self.installed_force = None
        self.installed = gevent.signal(signal.SIGINT, self.handle_int)

    def install_handler_force(self):
        if self.installed:
            self.installed.cancel()
            self.installed = None
        self.installed_force = gevent.signal(signal.SIGINT, self.handle_force)

    def handle_int(self):
        self.install_handler_force()

        gevent.spawn(self._confirm_enter_console)

    def handle_force(self):
        """
        User pressed ^C a second time. Send SIGTERM to ourself.
        """
        os.kill(os.getpid(), signal.SIGTERM)

    def _confirm_enter_console(self):
        start = time.time()
        sys.stdout.write("\n")
        enter_console = False
        while time.time() - start < ENTER_CONSOLE_TIMEOUT:
            sys.stdout.write(
                "\r{}{}Hit [ENTER], to launch console; [Ctrl+C] again to quit! [{:1.0f}s]{}".format(
                    bc.OKGREEN, bc.BOLD, ENTER_CONSOLE_TIMEOUT - (time.time() - start),
                    bc.ENDC))
            sys.stdout.flush()
            try:
                r, _, _ = select.select([sys.stdin], [], [], .5)
            except select.error as ex:
                sys.stdout.write("\n")
                # "Interrupted sytem call" means the user pressed ^C again
                if ex.args[0] == errno.EINTR:
                    self.handle_force()
                    return
                else:
                    raise
            if r:
                sys.stdin.readline()
                enter_console = True
                break
        if enter_console:
            sys.stdout.write("\n")
            self.installed_force.cancel()
            self.event.set()
        else:
            sys.stdout.write(
                "\n{}{}No answer after {}s. Resuming.{}\n".format(
                    bc.WARNING, bc.BOLD, ENTER_CONSOLE_TIMEOUT, bc.ENDC))
            sys.stdout.flush()
            # Restore regular handler
            self.install_handler()


class Console(BaseService):

    """A service starting an interactive ipython session when receiving the
    SIGSTP signal (e.g. via keyboard shortcut CTRL-Z).
    """

    name = 'console'

    def __init__(self, app):
        super(Console, self).__init__(app)
        self.interrupt = Event()
        self.console_locals = {}
        if app.start_console:
            self.start()
            self.interrupt.set()
        else:
            SigINTHandler(self.interrupt)

    def _stop_app(self):
        try:
            self.app.stop()
        except gevent.GreenletExit:
            pass

    def start(self):
        super(Console, self).start()

        class Eth(object):

            """
            convenience object to interact with the live chain
            """

            def __init__(this, app):
                this.app = app
                this.services = app.services
                this.stop = app.stop
                this.chainservice = app.services.chain
                this.chain = this.chainservice.chain
                this.coinbase = app.services.accounts.coinbase

            @property
            def pending(this):
                return this.chain.head_candidate

            head_candidate = pending

            @property
            def latest(this):
                return this.chain.head

            def transact(this, to, value=0, data='', sender=None,
                         startgas=25000, gasprice=60 * denoms.shannon):
                sender = normalize_address(sender or this.coinbase)
                to = normalize_address(to, allow_blank=True)
                nonce = this.pending.get_nonce(sender)
                tx = Transaction(nonce, gasprice, startgas, to, value, data)
                this.app.services.accounts.sign_tx(sender, tx)
                assert tx.sender == sender
                this.chainservice.add_transaction(tx)
                return tx

            def call(this, to, value=0, data='', sender=None,
                     startgas=25000, gasprice=60 * denoms.shannon):
                sender = normalize_address(sender or this.coinbase)
                to = normalize_address(to, allow_blank=True)
                block = this.head_candidate
                state_root_before = block.state_root
                assert block.has_parent()
                # rebuild block state before finalization
                parent = block.get_parent()
                test_block = block.init_from_parent(parent, block.coinbase,
                                                    timestamp=block.timestamp)
                for tx in block.get_transactions():
                    success, output = processblock.apply_transaction(test_block, tx)
                    assert success

                # apply transaction
                nonce = test_block.get_nonce(sender)
                tx = Transaction(nonce, gasprice, startgas, to, value, data)
                tx.sender = sender

                try:
                    success, output = processblock.apply_transaction(test_block, tx)
                except InvalidTransaction:
                    success = False

                assert block.state_root == state_root_before

                if success:
                    return output
                else:
                    return False

            def find_transaction(this, tx):
                try:
                    t, blk, idx = this.chain.index.get_transaction(tx.hash)
                except:
                    return {}
                return dict(tx=t, block=blk, index=idx)

            def new_contract(this, abi, address, sender=None):
                return ABIContract(sender or this.coinbase, abi, address, this.call, this.transact)

            def block_from_rlp(this, rlp_data):
                from eth_protocol import TransientBlock
                import rlp
                l = rlp.decode_lazy(rlp_data)
                return TransientBlock(l).to_block(this.chain.blockchain)

        try:
            from ethereum._solidity import solc_wrapper
        except ImportError:
            solc_wrapper = None
            pass

        try:
            import serpent
        except ImportError:
            serpent = None
            pass

        self.console_locals = dict(eth=Eth(self.app), solidity=solc_wrapper, serpent=serpent,
                                   denoms=denoms, true=True, false=False, Eth=Eth)

        for k, v in self.app.script_globals.items():
            self.console_locals[k] = v

    def _run(self):
        self.interrupt.wait()
        print('\n' * 2)
        print("Entering Console" + bc.OKGREEN)
        print("Tip:" + bc.OKBLUE)
        print("\tuse `{}lastlog(n){}` to see n lines of log-output. [default 10] ".format(
            bc.HEADER, bc.OKBLUE))
        print("\tuse `{}lasterr(n){}` to see n lines of stderr.".format(bc.HEADER, bc.OKBLUE))
        print("\tuse `{}help(eth){}` for help on accessing the live chain.".format(
            bc.HEADER, bc.OKBLUE))
        print("\n" + bc.ENDC)

        # runmultiple hack in place?
        if hasattr(self.console_locals['eth'].app, 'apps'):
            print('\n' * 2 + bc.OKGREEN)
            print("Hint:" + bc.OKBLUE)
            print('\tOther nodes are accessible from {}`eth.app.apps`{}').format(
                bc.HEADER, bc.OKBLUE)
            print('\tThey where automatically assigned to:')
            print("\t`{}eth1{}`".format(
                bc.HEADER, bc.OKBLUE))
            if len(self.console_locals['eth'].app.apps) > 3:
                print("\t {}...{}".format(
                    bc.HEADER, bc.OKBLUE))
            print("\t`{}eth{}{}`".format(
                bc.HEADER, len(self.console_locals['eth'].app.apps) - 1, bc.OKBLUE))
            print("\n" + bc.ENDC)

            # automatically assign different nodes to 'eth1.', 'eth2.'' , ....
            Eth = self.console_locals['Eth']
            for x in range(1, len(self.console_locals['eth'].app.apps)):
                self.console_locals['eth' + str(x)] = Eth(self.console_locals['eth'].app.apps[x])

        # Remove handlers that log to stderr
        root = getLogger()
        for handler in root.handlers[:]:
            if isinstance(handler, StreamHandler) and handler.stream == sys.stderr:
                root.removeHandler(handler)

        stream = cStringIO.StringIO()
        handler = StreamHandler(stream=stream)
        handler.formatter = Formatter("%(levelname)s:%(name)s %(message)s")
        root.addHandler(handler)

        def lastlog(n=10, prefix=None, level=None):
            """Print the last `n` log lines to stdout.
            Use `prefix='p2p'` to filter for a specific logger.
            Use `level=INFO` to filter for a specific level.

            Level- and prefix-filtering are applied before tailing the log.
            """
            lines = (stream.getvalue().strip().split('\n') or [])
            if prefix:
                lines = filter(lambda line: line.split(':')[1].startswith(prefix), lines)
            if level:
                lines = filter(lambda line: line.split(':')[0] == level, lines)
            for line in lines[-n:]:
                print(line)

        self.console_locals['lastlog'] = lastlog

        err = cStringIO.StringIO()
        sys.stderr = err

        def lasterr(n=1):
            """Print the last `n` entries of stderr to stdout.
            """
            for line in (err.getvalue().strip().split('\n') or [])[-n:]:
                print(line)

        self.console_locals['lasterr'] = lasterr

        IPython.start_ipython(argv=['--gui', 'gevent'], user_ns=self.console_locals)
        self.interrupt.clear()

        sys.exit(0)

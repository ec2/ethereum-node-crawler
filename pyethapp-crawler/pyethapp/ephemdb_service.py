from devp2p.service import BaseService
from gevent.event import Event
from ethereum.db import _EphemDB
from logging import getLogger

log = getLogger(__name__)


class EphemDB(_EphemDB, BaseService):

    name = 'db'

    def __init__(self, app):
        BaseService.__init__(self, app)
        _EphemDB.__init__(self)
        self.stop_event = Event()

    def _run(self):
        self.stop_event.wait()

    def stop(self):
        self.stop_event.set()
        # commit?
        log.info('closing db')

# -*- coding: utf8 -*-
import os

import lmdb
from devp2p.service import BaseService
from ethereum.db import BaseDB
from ethereum.slogging import get_logger
from gevent.event import Event

log = get_logger('db')

# unique objects to represent state in the transient store, the delete
# operation will store the DELETE constant in the transient store, and NULL is
# used to avoid conflicts with None, effectivelly allowing the user to store it
NULL = object()
DELETE = object()
TB = (2 ** 10) ** 4


class LmDBService(BaseDB, BaseService):
    """A service providing an interface to a lmdb."""

    name = 'db'
    default_config = dict()  # the defaults are defined in pyethapp.db_service

    def __init__(self, app):
        assert app.config['data_dir']

        BaseService.__init__(self, app)

        db_directory = os.path.join(app.config['data_dir'], 'lmdb')

        self.env = lmdb.Environment(db_directory, map_size=TB)
        self.db_directory = db_directory
        self.uncommitted = dict()
        self.stop_event = Event()

    def _run(self):
        self.stop_event.wait()

    def stop(self):
        self.stop_event.set()

    def put(self, key, value):
        self.uncommitted[key] = value

    def delete(self, key):
        self.uncommitted[key] = DELETE

    def inc_refcount(self, key, value):
        self.put(key, value)

    def dec_refcount(self, key):
        pass

    def put_temporarily(self, key, value):
        self.inc_refcount(key, value)
        self.dec_refcount(key)

    def reopen(self):
        self.env.close()
        del self.env
        # the map_size is stored in the database itself after it's first created
        self.env = lmdb.Environment(self.db_directory)

    def get(self, key):
        value = self.uncommitted.get(key, NULL)

        if value is DELETE:
            raise KeyError('key not in db')

        if value is NULL:
            with self.env.begin(write=False) as transaction:
                value = transaction.get(key, NULL)

            if value is NULL:
                raise KeyError('key not in db')

            self.uncommitted[key] = value

        return value

    def commit(self):
        keys_to_delete = (
            key
            for key, value in self.uncommitted.items()
            if value is DELETE
        )

        items_to_insert = (
            (key, value)
            for key, value in self.uncommitted.items()
            if value not in (DELETE, NULL)  # NULL shouldn't happen
        )

        with self.env.begin(write=True) as transaction:
            for key in keys_to_delete:
                transaction.delete(key)

            cursor = transaction.cursor()
            cursor.putmulti(items_to_insert, overwrite=True)

    def revert_refcount_changes(self, epoch):
        pass

    def commit_refcount_changes(self, epoch):
        pass

    def cleanup(self, epoch):
        pass

    def __contains__(self, key):
        try:
            self.get(key)
        except KeyError:
            return False
        return True

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.db == other.db

    def __repr__(self):
        return '<DB at %d uncommitted=%d>' % (id(self.env), len(self.uncommitted))

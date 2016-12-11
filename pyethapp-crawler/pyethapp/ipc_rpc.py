#!/usr/bin/env python
"""Derived from https://groups.google.com/d/topic/gevent/5__B9hOup38/discussion
"""
import _socket
import os
import pwd
from gevent.server import StreamServer
import tempfile


def unlink(path):
    from errno import ENOENT
    try:
        os.unlink(path)
    except OSError, ex:
        if ex.errno != ENOENT:
            raise


def link(src, dest):
    from errno import ENOENT
    try:
        os.link(src, dest)
    except OSError, ex:
        if ex.errno != ENOENT:
            raise


def bind_unix_listener(path, backlog=50, user=None):
    pid = os.getpid()
    tempname = '%s.%s.tmp' % (path, pid)
    backname = '%s.%s.bak' % (path, pid)
    unlink(tempname)
    unlink(backname)
    link(path, backname)
    try:
        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        sock.setblocking(0)
        sock.bind(tempname)
        try:

            if user is not None:
                user = pwd.getpwnam(user)
                os.chown(tempname, user.pw_uid, user.pw_gid)
                os.chmod(tempname, 0600)
            sock.listen(backlog)
            try:
                os.rename(tempname, path)
            except:
                os.rename(backname, path)
                backname = None
                raise
            tempname = None
            return sock
        finally:
            if tempname is not None:
                unlink(tempname)
    finally:
        if backname is not None:
            unlink(backname)


def handle(socket, address):
    print socket, address
    print socket.recv(4096)
    socket.sendall('pong\n')


def serve(sock, handler=handle):
    StreamServer(sock, handler).serve_forever()

if __name__ == "__main__":
    path = os.path.join(tempfile.gettempdir(), "echo.ipc")
    print "Starting echo sever..."
    print "Test it with:\n\techo 'ping'| socat - {}".format(path)
    serve(bind_unix_listener(path))

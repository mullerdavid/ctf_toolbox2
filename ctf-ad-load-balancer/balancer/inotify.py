"""Tiny ctypes wrapper around Linux inotify (no third-party deps)."""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import struct

IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000

WATCH_MASK = (IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO
              | IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF)
GONE_MASK = IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED

_EVENT = struct.Struct("iIII")


class Inotify:
    def __init__(self, path: str):
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if fd < 0:
            err = ctypes.get_errno()
            raise OSError(err, f"inotify_init1: {os.strerror(err)}")
        wd = libc.inotify_add_watch(fd, os.fsencode(path), WATCH_MASK)
        if wd < 0:
            err = ctypes.get_errno()
            os.close(fd)
            raise OSError(err, f"inotify_add_watch: {os.strerror(err)}")
        self.fd = fd

    def read_events(self) -> list[tuple[int, str]]:
        """Return [(mask, filename)] for all pending events (non-blocking)."""
        events = []
        while True:
            try:
                data = os.read(self.fd, 65536)
            except BlockingIOError:
                return events
            if not data:
                return events
            offset = 0
            while offset + _EVENT.size <= len(data):
                _wd, mask, _cookie, length = _EVENT.unpack_from(data, offset)
                offset += _EVENT.size
                name = data[offset:offset + length].rstrip(b"\0").decode("utf-8", "replace")
                offset += length
                events.append((mask, name))

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 VyOS Inc, Kyrylo Yatsenko

import netns

from scapy.all import AsyncSniffer
from scapy.config import conf

import threading

from contextlib import nullcontext

class ScapyNetNS(netns.NetNS):
    def __init__(self, gear):
        netns.NetNS.__init__(self, nspid=gear.net.pid)

    def __enter__(self):
        netns.NetNS.__enter__(self)
        # Solution from https://github.com/secdev/scapy/issues/3467
        # But order change is important! Otherwise conf.iface is updated wrogly
        conf.route.resync()  # Reload IPv4 routes
        conf.ifaces.reload()  # Reload interface list

    def __exit__(self, exc_type, exc_value, traceback):
        ret = netns.NetNS.__exit__(self, exc_type, exc_value, traceback)
        conf.route.resync()  # Restore IPv4 routes
        conf.ifaces.reload()  # Restore interface list
        return ret


class AsyncSnifferNetNS(AsyncSniffer):
    def __init__(self, gear, iface, wait_on_start=False, wait_on_start_timeout=5, lock=nullcontext(), *args, **kwargs):
        self._wait_on_start = wait_on_start
        self._wait_on_start_timeout = wait_on_start_timeout

        if wait_on_start:
            self._event = threading.Event()
            kwargs['started_callback'] = lambda event=self._event: event.set()

        from scapy.interfaces import resolve_iface

        with lock:
            with ScapyNetNS(gear):
                base_class = resolve_iface(iface).l2listen()

        class SocketNetNS(base_class):
            _lock = lock
            _gear = gear
            def __init__(self, *args, **kwargs):
                with self._lock:
                    with ScapyNetNS(self._gear):
                        base_class.__init__(self, *args, **kwargs)

            def close(self, *args, **kwargs):
                with self._lock:
                    with ScapyNetNS(self._gear):
                        base_class.close(self, *args, **kwargs)

        AsyncSniffer.__init__(self, L2socket=SocketNetNS, iface=iface, *args, **kwargs)

    def start(self, *args, **kwargs):
        AsyncSniffer.start(self, *args, **kwargs)
        if self._wait_on_start:
            return self._event.wait(timeout=self._wait_on_start_timeout)
        return True

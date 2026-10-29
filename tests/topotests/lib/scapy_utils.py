# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2026 VyOS Inc, Kyrylo Yatsenko

# Scapy is nice util to send raw packets and sniff them
# Using netns it is possible to easily send/capture packets
# in networking namespace of any topotest routers
#
# == Usage example sending packet:
#
# ```
# from lib.scapy_utils import ScapyNetNS
# from scapy.all import Ether, sendp
#
# ...
#   with ScapyNetNS(tgen.gears['r1']):
#       pkt = Ether(src='00:00:00:00:00:19', dst="ff:ff:ff:ff:ff:ff", type=31237)
#       sendp([pkt] * 5, iface='r1-eth1')
# ```
#
# Will send 5 broadcast Ethernet packets from MAC '00:00:00:00:00:19' with protocol
# 0x7a05, from interface r1-eth1 under gear r1.
#
#
# == Usage example capturing packets:
#
# ```
# from lib.scapy_utils import AsyncSnifferNetNS
#
#    ...
#    sniffer = AsyncSnifferNetNS(
#        tgen.gears["r2"],
#        wait_on_start=True,
#        count=5,
#        filter="ether proto 31237",
#        iface="r2-eth1",
#    )
#    sniffer.start() # will wait till capturing takes place because of wait_on_start
#    sniffer.join(timeout=5) # will stop as soon as 5 packets are captured
#    sniffer.stop(ignore_stopped=True) # unlike AsyncSniffer doesn't raise in case of already stopped
#
#    res = sniffer.results
#    received_packets_n = len(res) if res else 0
#    assert received_packets_n == 5, "Received wrong number of packets on r2-eth1"
#
#
# == Thread safety
#
# ScapyNetNS and AsyncSnifferNetNS are not threadsafe by themselves!  Each
# edits global state of scapy. If you need to use several of them
# asynchronously (or use other scapy functions that send/receive/work with
# routes or interfaces out of ScapyNetNS), use threading.Lock.
#
# AsyncSnifferNetNS accepts `lock` in constructor that it locks each time
# it switches network namespace. Use same lock for each usage of ScapyNetNS
# and each AsyncSnifferNetNS that may run simultaneously, e. g.:
#
# ```
#    lock = threading.Lock()
#
#    # Prepare async sniffers
#    sniffers = []
#    for rname in ('r2', 'r3'):
#        router = tgen.gears[rname]
#        intf = f"{rname}-eth0"
#
#        sniffers.append(AsyncSnifferNetNS(
#            router,
#            lock=lock,
#            ...
#        ))
#        ...
#
#    with lock:
#        with ScapyNetNS(tgen.gears['r1']):
#            pkt = Ether(src='00:00:00:00:00:19', dst="ff:ff:ff:ff:ff:ff", type=31237)
#            sendp([pkt] * 5, iface='r1-eth1')
#
#    ... join/stop/assert on sniffers
# ```
#
# Also note that netns.py has a bug: when entering context NetNS, network
# namespace of main thread is stored, not thread-specific one, so if they
# differ, wrong one will be restored. One more reason to use locks as described
# above. (as of writing netns.py has version 1.0)

from lib import netns

from scapy.all import AsyncSniffer, Scapy_Exception
from scapy.config import conf

import threading

from contextlib import nullcontext


def _reload_scapy_after_netns_change():
    # Solution from https://github.com/secdev/scapy/issues/3467
    # But order change is important! Otherwise conf.iface is updated wrongly
    conf.route.resync()  # Reload IPv4 routes
    conf.route6.resync()  # Reload IPv6 routes
    conf.ifaces.reload()  # Reload interface list
    conf.netcache.flush()  # Clear all caches


class ScapyNetNS(netns.NetNS):
    """
    Context manager for network namespace that is used for
    gear in topotests. Allows to run scapy functions as if from
    router right in main Python code
    """

    def __init__(self, gear):
        netns.NetNS.__init__(self, nspid=gear.net.pid)

    def __enter__(self):
        netns.NetNS.__enter__(self)
        try:
            _reload_scapy_after_netns_change()
        except Exception:
            netns.NetNS.__exit__(self, None, None, None)
            raise

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        ret = netns.NetNS.__exit__(self, exc_type, exc_value, traceback)
        _reload_scapy_after_netns_change()
        return ret


class AsyncSnifferNetNS(AsyncSniffer):
    """
    Wrapper around AsyncSniffer that captures packets in network namespace that
    is used for gear in topotests.
    """

    def __init__(
        self,
        gear,
        iface,
        wait_on_start=False,
        wait_on_start_timeout=5,
        lock=nullcontext(),
        *args,
        **kwargs,
    ):
        self._wait_on_start = wait_on_start
        self._wait_on_start_timeout = wait_on_start_timeout

        if wait_on_start:
            if "started_callback" in kwargs:
                # Can be implemented as wrapper if needed
                raise RuntimeError(
                    "AsyncSnifferNetNS: wait_on_start and started_callback are incompatible"
                )
            self._event = threading.Event()
            kwargs["started_callback"] = lambda event=self._event: event.set()

        ifaces = []
        if isinstance(iface, list):
            ifaces = iface
        elif isinstance(iface, dict):
            ifaces = list(iface.keys())
        else:
            ifaces = [iface]

        from scapy.interfaces import resolve_iface

        with lock:
            with ScapyNetNS(gear):
                base_class = resolve_iface(ifaces[0]).l2listen()
                for ifname in ifaces[1:]:
                    other_base_class = resolve_iface(ifname).l2listen()
                    if other_base_class != base_class:
                        raise RuntimeError(
                            f"AsyncSnifferNetNS: resolve_iface returned different base classes for {ifaces[0]} and {ifname}. Unsupported"
                        )

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
            if not self._event.wait(timeout=self._wait_on_start_timeout):
                # May raise exception with reason of failure
                self.stop()
                # If not, raise one ourselves
                raise Scapy_Exception(
                    f"AsyncSnifferNetNS.start: failed to start sniffer within waiting time {self._wait_on_start_timeout}"
                )

    def stop(self, *args, ignore_stopped=False, **kwargs):
        """
        Thin wrapper over AsyncSniffer.stop.

        If ignore_stopped is True, ignore Exception raised when sniffer is already stopped
        """
        if not ignore_stopped:
            return AsyncSniffer.stop(self, *args, **kwargs)
        ret = None
        try:
            ret = AsyncSniffer.stop(self, *args, **kwargs)
        except Scapy_Exception as e:
            if e.args[0] not in (
                "Not started !",
                "Not running ! (check .running attr)",
            ):
                raise
            # AsyncSniffer._run has a little additional code after setting self.running = False
            # Wait till thread is joined, a second should be more than enough
            self.join(timeout=1)
            if self.thread and self.thread.is_alive():
                raise RuntimeError("AsyncSnifferNetNS: couldn't stop thread")
        return ret

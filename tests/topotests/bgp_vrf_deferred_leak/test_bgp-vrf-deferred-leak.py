#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp-vrf-deferred-leak.py
#
# Copyright (c) 2026 VyOS, Inc; Kyrylo Yatsenko
#

"""
test_bgp-vrf-deferred-leak.py: Test vrf route leaking for deffered routes
"""

import os
import sys
from functools import partial
import pytest
import json

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.checkping import check_ping

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for router in router_list.values():
        router.run("/bin/bash {}/setup_vrfs".format(CWD))
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


# see comment to vpn_leak_postchange_all
def test_vrf_deffered_route_leak():
    logger.info(
        "Ensure that deffered route leaks are processed properly (the ones exported before default bgp router is created)"
    )
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Wait for route to be known to bgp vrf instance
    expect = {"routes": {"10.0.5.0/24": [{"valid": True}]}}
    test_func = partial(
        topotest.router_json_cmp, r1, "show bgp vrf NONNA ipv4 unicast json", expect
    )
    result, diff = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result, "Initial route in BGP VRF didn't appear:\n{}".format(diff)

    # Now enable bgp router in default VRF
    r1.vtysh_cmd("configure terminal\nrouter bgp 65500")

    # Verify deferred route leak was processed properly
    expect = {
        "routes": {
            "routeDistinguishers": {
                "65500:100": {
                    "10.0.5.0/24": [{"valid": True}],
                },
            },
        }
    }
    test_func = partial(topotest.router_json_cmp, r1, "show bgp ipv4 vpn json", expect)
    result, diff = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result, "BGP VRF deffered route leak check failed:\n{}".format(diff)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

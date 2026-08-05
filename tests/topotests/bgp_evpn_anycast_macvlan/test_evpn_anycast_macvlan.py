#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_evpn_anycast_macvlan.py
#
# Copyright (c) 2026 by
# VyOS, Inc.
# Kyrylo Yatsenko
#
# Copyright (C) 2026 Robin Christ, partimus GmbH
#

"""
test_evpn_anycast_macvlan.py: EVPN anycast gateway on macvlan (VRR) devices,
including interface lifecycle edge cases.
"""

import json
import os
import platform
import pytest
import re
import sys

from functools import partial
from lib.checkping import check_ping

pytestmark = [pytest.mark.bgpd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.common_config import step

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

#####################################################
##
##   Network Topology Definition
##
## See topology picture at test_evpn_anycast_macvlan.png
#####################################################


host_ips = {
    "host11": "192.168.1.10",
    "host12": "192.168.2.10",
    "host21": "192.168.1.20",
    "host22": "192.168.2.20",
}

host_mac_map = {
    "host11": "00:50:79:66:68:11",
    "host12": "00:50:79:66:68:12",
    "host21": "00:50:79:66:68:21",
    "host22": "00:50:79:66:68:22",
}

hosts = list(host_mac_map.keys())
routers = ["r1", "r2"]

# The tenant VRF the anycast gateways live in, and a second tenant VRF used
# only as a move target for the VRF-change scenarios.  It carries no VNI of
# its own: what those scenarios turn on is whether the macvlan is still in
# the same VRF as its SVI, not what the other VRF offers.
VRF = "RED"
VRF_ALT = "BLUE"
L3VNI = 1000

GW_MAC = "00:aa:aa:aa:aa:aa"
GW_IPS = {100: "192.168.1.1", 200: "192.168.2.1"}
SUBNETS = {100: "192.168.1.0/24", 200: "192.168.2.0/24"}

# The host behind the *other* gateway, per VLAN; this is the remote MAC/IP
# each router must learn over EVPN.
REMOTE_HOST = {
    "r1": {100: "host21", 200: "host22"},
    "r2": {100: "host11", 200: "host12"},
}
REMOTE_VTEP = {"r1": "1.1.1.2", "r2": "1.1.1.1"}

# Second, non-anycast macvlan on the same SVI, used by the two-macvlan
# scenarios.
SECOND_MACVLAN_MAC = "00:aa:aa:aa:aa:bb"


def build_topo(tgen):
    """
    EVPN Anycast Topology -
    1. Two gateways: r1, r2
    2. Four hosts: host11, host12, host21, host22
        Hosts host1* are connected to r1, hosts host2* - to r2
        Hosts host*1 are in 192.168.1.0/24 network
        Hosts host*2 are in 192.168.2.0/24 network
    """

    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("host11")
    tgen.add_router("host12")
    tgen.add_router("host21")
    tgen.add_router("host22")

    # Create switches
    switch = tgen.add_switch("sr1r2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s11")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["host11"])

    switch = tgen.add_switch("s12")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["host12"])

    switch = tgen.add_switch("s21")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["host21"])

    switch = tgen.add_switch("s22")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["host22"])


def router_compare_json_output(rname, command, reference, count=130, wait=1):
    "Compare router JSON output"

    logger.info(f'Comparing router "{rname}" "{command}" output')

    tgen = get_topogen()
    filename = f"{CWD}/{rname}/{reference}"
    with open(filename) as f:
        expected = json.loads(f.read())

    # Run test function until we get an result.
    test_func = partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
    _, diff = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    assertmsg = f'"{rname}" JSON output mismatches the expected result'
    assert diff is None, assertmsg


#####################################################
##
##   Tests starting
##
#####################################################


def config_vrf(node):
    """
    Create the tenant VRFs on node.  VRF_ALT carries no VNI; it only exists
    as a move target for the macvlan/SVI VRF-change scenarios.
    """
    node.cmd_raises(f"ip link add {VRF} type vrf table 111")
    node.cmd_raises(f"ip link set dev {VRF} up")
    node.cmd_raises(f"ip link add {VRF_ALT} type vrf table 222")
    node.cmd_raises(f"ip link set dev {VRF_ALT} up")


def config_bridge(node):
    """
    Create a VLAN aware bridge
    """
    node.cmd_raises("ip link add dev br0 type bridge")
    node.cmd_raises("ip link set dev br0 type bridge vlan_filtering 1")
    node.cmd_raises("/sbin/bridge vlan add dev br0 vid 100 self")
    node.cmd_raises("/sbin/bridge vlan add dev br0 vid 200 self")
    node.cmd_raises("/sbin/bridge vlan add dev br0 vid 1000 self")
    node.cmd_raises("ip link set dev br0 up")
    node.cmd_raises(f"/sbin/bridge fdb add {GW_MAC} dev br0 self local")


def config_interface_vid(node, ifname, vid):
    node.cmd_raises(f"ip link set dev {ifname} master br0")
    node.cmd_raises(f"/sbin/bridge link set dev {ifname} isolated off")
    node.cmd_raises(f"/sbin/bridge vlan del dev {ifname} vid 1 master")
    node.cmd_raises(
        f"/sbin/bridge vlan add dev {ifname} vid {vid} pvid untagged master"
    )


def config_vxlan(node, lo_addr):
    node.cmd_raises(
        f"ip link add vxlan0 type vxlan dstport 4789 external df unset tos inherit ttl 64 nolearning local {lo_addr} dev lo"
    )
    node.cmd_raises("ip link set dev vxlan0 mtu 1500")
    node.cmd_raises("ip link set dev vxlan0 master br0")
    node.cmd_raises("/sbin/bridge vlan del dev vxlan0 vid 1 master")
    node.cmd_raises("ip link set dev vxlan0 up")
    node.cmd_raises("/sbin/bridge link set dev vxlan0 vlan_tunnel on")
    node.cmd_raises("/sbin/bridge link set dev vxlan0 neigh_suppress on learning off")
    node.cmd_raises("ip link set vxlan0 type bridge_slave learning off")


def config_vlan(node, vid):
    node.cmd_raises(f"ip link add link br0 name br0.{vid} type vlan id {vid}")
    node.cmd_raises(f"ip link set dev br0.{vid} master {VRF}")
    node.cmd_raises(f"ip link set dev br0.{vid} up")
    node.cmd_raises(f"/sbin/bridge vlan add dev vxlan0 vid {vid}")
    node.cmd_raises(f"/sbin/bridge vlan add dev vxlan0 vid {vid} tunnel_info id {vid}")


def config_macvlan(node, vid, addr):
    node.cmd_raises(
        f"ip link add macvlan{vid} link br0.{vid} type macvlan mode private"
    )
    node.cmd_raises(f"ip link set dev macvlan{vid} address {GW_MAC}")
    node.cmd_raises(f"ip link set dev macvlan{vid} master {VRF}")
    node.cmd_raises(f"ip addr add {addr}/24 dev macvlan{vid} brd +")
    node.cmd_raises(f"ip link set dev macvlan{vid} up")
    node.cmd_raises(f"/sbin/sysctl -w net.ipv4.conf.macvlan{vid}.arp_accept=1")


def delete_macvlan(node, vid):
    node.cmd_raises(f"ip link del macvlan{vid}")


def config_macvlan_enslave_last(node, vid, addr):
    """
    Same result as config_macvlan, but the interface is up before it is
    enslaved into the VRF - the other valid provisioning order.
    """
    node.cmd_raises(
        f"ip link add macvlan{vid} link br0.{vid} type macvlan mode private"
    )
    node.cmd_raises(f"ip link set dev macvlan{vid} address {GW_MAC}")
    node.cmd_raises(f"ip addr add {addr}/24 dev macvlan{vid} brd +")
    node.cmd_raises(f"ip link set dev macvlan{vid} up")
    node.cmd_raises(f"/sbin/sysctl -w net.ipv4.conf.macvlan{vid}.arp_accept=1")
    node.cmd_raises(f"ip link set dev macvlan{vid} master {VRF}")


def config_second_macvlan(node, vid):
    """
    A second, non-anycast macvlan on the same SVI, left in the default VRF.
    It must never take over the anycast gateway (VRR) role from the
    tenant-VRF macvlan, in either creation order.
    """
    name = f"macvlan{vid}d"
    node.cmd_raises(f"ip link add {name} link br0.{vid} type macvlan mode private")
    node.cmd_raises(f"ip link set dev {name} address {SECOND_MACVLAN_MAC}")
    node.cmd_raises(f"ip link set dev {name} up")


def delete_second_macvlan(node, vid):
    node.cmd(f"ip link del macvlan{vid}d")


def config_lo(node, lo_addr):
    node.cmd_raises(f"ip addr add {lo_addr}/32 dev lo brd +")
    node.cmd_raises("ip link set dev lo up")


def config_router(node, name, lo_addr):
    config_vrf(node)
    config_bridge(node)
    config_interface_vid(node, f"{name}-eth1", 100)
    config_interface_vid(node, f"{name}-eth2", 200)
    config_vxlan(node, lo_addr)
    config_vlan(node, 100)
    config_vlan(node, 200)
    config_vlan(node, 1000)
    config_macvlan(node, 100, GW_IPS[100])
    config_macvlan(node, 200, GW_IPS[200])
    config_lo(node, lo_addr)


def config_host(host_name, host):
    """
    Setup host with hard-coded MAC/IP
    """
    ifname = host_name + "-eth0"
    host_ip = host_ips[host_name]
    host_mac = host_mac_map[host_name]
    host.run(f"ip addr add {host_ip}/24 dev {ifname}")
    host.run(f"ip link set dev {ifname} address {host_mac}")


def config_hosts(tgen):
    for host_name in hosts:
        host = tgen.gears[host_name]
        config_host(host_name, host)


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.18") < 0:
        pytest.skip(
            f'Skipping EVPN anycast macvlan test, kernel "{krel}" is too old',
            allow_module_level=True,
        )

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, f"{rname}/frr.conf"))

    # Putting these below start_router still work, but significantly slower
    config_router(tgen.gears["r1"], "r1", "1.1.1.1")
    config_router(tgen.gears["r2"], "r2", "1.1.1.2")

    tgen.start_router()

    # Putting this above start_router ruins all addresses/routes
    config_hosts(tgen)


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


#####################################################
##
##   Helpers
##
#####################################################


def dump_neigh_state(router, vid):
    """
    Log the neighbor state of the SVI and its VRR macvlan, plus the EVPN
    view - this is the evidence for where the state diverges.
    """
    tgen = get_topogen()
    node = tgen.gears[router]
    for dev in (f"br0.{vid}", f"macvlan{vid}"):
        logger.info(
            f"{router}: ip neigh show dev {dev}:\n"
            + node.run(f"ip neigh show dev {dev}")
        )
    logger.info(
        f"{router}: show evpn arp-cache vni {vid}:\n"
        + node.vtysh_cmd(f"show evpn arp-cache vni {vid}")
    )


def _dump_state(router, tag):
    """
    Full evidence dump for a router.  Mechanism evidence only - never a
    pass/fail input.
    """
    tgen = get_topogen()
    node = tgen.gears[router]
    logger.info("=========== %s : %s ===========", router, tag)
    for cmd in (
        "show evpn vni json",
        "show evpn vni 100 json",
        "show evpn vni 200 json",
        f"show evpn vni {L3VNI} json",
        "show evpn mac vni 100 json",
        "show evpn mac vni 200 json",
        "show evpn arp-cache vni all json",
        f"show bgp l2vpn evpn vni {L3VNI} json",
    ):
        logger.info("--- vtysh %s\n%s", cmd, node.vtysh_cmd(cmd))
    for cmd in (
        "ip -d link show",
        "ip addr show",
        "ip neigh show",
        "bridge fdb show dev vxlan0",
        f"ip route show vrf {VRF}",
        f"ip route show vrf {VRF_ALT}",
    ):
        logger.info("--- shell %s\n%s", cmd, node.run(cmd))


def _vtysh_json(router, cmd):
    tgen = get_topogen()
    return json.loads(tgen.gears[router].vtysh_cmd(cmd))


def _expect_json(router, cmd, expected, count=60, wait=1):
    tgen = get_topogen()
    test_func = partial(topotest.router_json_cmp, tgen.gears[router], cmd, expected)
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    return result


def _expect_shell(router, cmd, matcher, count=60, wait=1):
    """Poll a shell command until matcher(output) is True.  Returns (ok, output)."""
    tgen = get_topogen()
    node = tgen.gears[router]
    state = {"out": ""}

    def _check():
        state["out"] = node.run(cmd)
        return matcher(state["out"])

    _, ok = topotest.run_and_expect(_check, True, count=count, wait=wait)
    return ok, state["out"]


def _l3vni_l2vnis(router, l3vni=L3VNI):
    """L2VNIs zebra has attached to the given L3VNI."""
    return _vtysh_json(router, f"show evpn vni {l3vni} json").get("l2Vnis", [])


def _bgp_l3vni_l2vnis(router, l3vni=L3VNI):
    """L2VNIs bgpd has attached to the given L3VNI's tenant VRF."""
    return _vtysh_json(router, f"show bgp l2vpn evpn vni {l3vni} json").get(
        "l2Vnis", []
    )


def _neigh_on_dev(router, dev, ip):
    """
    Return the neighbor entry for 'ip' on 'dev', or None.
    """
    tgen = get_topogen()
    output = tgen.gears[router].run(f"ip neigh show dev {dev}")
    for line in output.splitlines():
        fields = line.split()
        if fields and fields[0] == ip:
            return line.strip()
    return None


def check_neigh_on_dev(
    router, dev, ip, mac, count=30, wait=1, installed_by_zebra=False
):
    """
    Assert that there is a usable neighbor entry for ip/mac on dev.

    With installed_by_zebra the entry additionally has to be the one zebra
    installed for a remote neighbor (extern_learn), not one that was
    resolved locally by ARP.
    """

    def _check():
        entry = _neigh_on_dev(router, dev, ip)
        if entry is None:
            return f"no neighbor entry for {ip} on {router}:{dev}"
        if mac not in entry:
            return f"neighbor entry for {ip} on {router}:{dev} has wrong mac: {entry}"
        if re.search(r"\b(FAILED|INCOMPLETE)\b", entry):
            return f"neighbor entry for {ip} on {router}:{dev} is not usable: {entry}"
        if installed_by_zebra and "extern_learn" not in entry:
            return (
                f"neighbor entry for {ip} on {router}:{dev} was not installed by "
                f"zebra: {entry}"
            )
        return None

    logger.info(f"[+] check neighbor {ip} ({mac}) on {router}:{dev}")
    _, result = topotest.run_and_expect(_check, None, count=count, wait=wait)
    assert result is None, result


def check_no_zebra_neigh_on_dev(router, dev, ip, count=20, wait=1):
    """
    Assert that zebra has no *remote* (extern_learn) neighbor for ip on dev.

    A locally resolved entry may legitimately exist - the macvlan can ARP
    for the address through the bridge - so only zebra-installed entries are
    rejected here.
    """

    def _check():
        entry = _neigh_on_dev(router, dev, ip)
        if entry is not None and "extern_learn" in entry:
            return (
                f"zebra-installed neighbor {ip} unexpectedly present on "
                f"{router}:{dev}: {entry}"
            )
        return None

    logger.info(f"[-] check no zebra neighbor {ip} on {router}:{dev}")
    _, result = topotest.run_and_expect(_check, None, count=count, wait=wait)
    assert result is None, result


def assert_anycast_gw_state(
    router,
    vid,
    tenant_vrf=VRF,
    vrr_dev=None,
    expect_vrr=True,
    count=60,
):
    """
    The one shared end-state assertion for an anycast gateway L2VNI.

    Every scenario and every control calls this; nothing duplicates its
    checks.  Parameters:

      router      - "r1" or "r2"
      vid         - the L2VNI / VLAN id (100 or 200)
      tenant_vrf  - the VRF the SVI is expected to be in.  Membership in the
                    L3VNI is asserted positively when this is the VNI-carrying
                    tenant VRF and negatively otherwise.
      vrr_dev     - the macvlan expected to act as anycast gateway
                    (default macvlan<vid>)
      expect_vrr  - whether that macvlan must carry the remote neighbours and
                    the connected route.  False means "must not" (checked
                    only after the positive SVI-side assertions converged).

    Exact numMacs/numArpNd counts are deliberately not asserted: locally
    learned entries come and go with ARP ageing and would make the helper
    flaky.  Specific expected entries are asserted instead.
    """

    if vrr_dev is None:
        vrr_dev = f"macvlan{vid}"

    svi = f"br0.{vid}"
    remote_host = REMOTE_HOST[router][vid]
    remote_ip = host_ips[remote_host]
    remote_mac = host_mac_map[remote_host]
    remote_vtep = REMOTE_VTEP[router]
    in_l3vni = tenant_vrf == VRF

    # --- zebra: the VNI itself -------------------------------------------
    step(f"{router}: zebra must report L2VNI {vid} in {tenant_vrf} on {svi}")
    expected = {
        "vni": vid,
        "type": "L2",
        "tenantVrf": tenant_vrf,
        "sviInterface": svi,
        "vxlanInterface": "vxlan0",
    }
    result = _expect_json(router, f"show evpn vni {vid} json", expected, count=count)
    if result is not None:
        _dump_state(router, f"FAILED vni state, vid {vid}")
    assert result is None, (
        f"{router}: L2VNI {vid} state wrong (expected tenant VRF {tenant_vrf}, "
        f"SVI {svi}): {result}"
    )

    # --- zebra: remote MAC and neighbour ---------------------------------
    step(f"{router}: zebra must know {remote_mac} as remote in L2VNI {vid}")
    expected = {"macs": {remote_mac: {"type": "remote", "remoteVtep": remote_vtep}}}
    result = _expect_json(
        router, f"show evpn mac vni {vid} json", expected, count=count
    )
    assert result is None, f"{router}: remote MAC {remote_mac} missing: {result}"

    step(f"{router}: zebra must know {remote_ip} as remote neighbour in L2VNI {vid}")
    expected = {remote_ip: {"type": "remote", "mac": remote_mac}}
    result = _expect_json(
        router, f"show evpn arp-cache vni {vid} json", expected, count=count
    )
    assert result is None, f"{router}: remote neighbour {remote_ip} missing: {result}"

    # --- zebra / bgpd: L2VNI to L3VNI association ------------------------
    step(f"{router}: L2VNI {vid} L3VNI {L3VNI} association (expected: {in_l3vni})")
    _, ok = topotest.run_and_expect(
        lambda: (vid in _l3vni_l2vnis(router)) == in_l3vni, True, count=30, wait=1
    )
    assert ok, (
        f"{router}: zebra L3VNI {L3VNI} l2Vnis={_l3vni_l2vnis(router)}, expected "
        f"L2VNI {vid} {'present' if in_l3vni else 'absent'}"
    )

    _, ok = topotest.run_and_expect(
        lambda: (vid in _bgp_l3vni_l2vnis(router)) == in_l3vni, True, count=30, wait=1
    )
    assert ok, (
        f"{router}: bgpd L3VNI {L3VNI} l2Vnis={_bgp_l3vni_l2vnis(router)}, expected "
        f"L2VNI {vid} {'present' if in_l3vni else 'absent'}"
    )

    # --- forwarding state: fdb of the vxlan device -----------------------
    step(f"{router}: the fdb must hold {remote_mac} towards {remote_vtep}")
    ok, out = _expect_shell(
        router,
        "bridge fdb show dev vxlan0",
        lambda o: re.search(rf"{remote_mac}.*dst {re.escape(remote_vtep)}", o)
        is not None,
        count=count,
    )
    assert ok, f"{router}: fdb missing remote MAC {remote_mac}:\n{out}"

    # --- forwarding state: the remote neighbour on the SVI ---------------
    check_neigh_on_dev(
        router, svi, remote_ip, remote_mac, count=count, installed_by_zebra=True
    )

    # --- forwarding state: the anycast gateway macvlan -------------------
    if expect_vrr:
        check_neigh_on_dev(
            router,
            vrr_dev,
            remote_ip,
            remote_mac,
            count=count,
            installed_by_zebra=True,
        )

        step(
            f"{router}: {SUBNETS[vid]} must be connected via {vrr_dev} in {tenant_vrf}"
        )
        ok, out = _expect_shell(
            router,
            f"ip route show vrf {tenant_vrf}",
            lambda o: re.search(rf"{re.escape(SUBNETS[vid])} dev {vrr_dev}\b", o)
            is not None,
            count=count,
        )
        assert ok, (
            f"{router}: connected route {SUBNETS[vid]} via {vrr_dev} missing from "
            f"vrf {tenant_vrf}:\n{out}"
        )
    else:
        # Negative check, only now that the positive SVI-side state above
        # has converged - checking for absence before the positive state
        # settles races against transients.
        check_no_zebra_neigh_on_dev(router, vrr_dev, remote_ip)


#####################################################
##
##   Tests
##
#####################################################


def test_01_ping_all_hosts(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # check ping of all hosts to hosts
    for host1_name in hosts:
        for host2_name in hosts:
            if host1_name == host2_name:
                continue
            check_ping(host1_name, host_ips[host2_name], True, 130, 1)


def test_02_evpn_arp_cache(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Fill in arp-cache by ping
    check_ping("host11", host_ips["host22"], True, 130, 1)
    check_ping("host12", host_ips["host21"], True, 30, 1)
    # Check
    for router in routers:
        router_compare_json_output(
            router,
            "show evpn arp-cache vni all json",
            "show_evpn_arp_cache_vni_all.ref",
        )


def test_03_baseline_conventional_order(tgen):
    """
    The reference control.  The gateways were provisioned in the
    conventional order (create, set MAC, enslave into the tenant VRF while
    still down, address, up), which is what setup_module does.

    Everything downstream re-uses assert_anycast_gw_state(); if this test
    fails, the assertions themselves are wrong and no other verdict in this
    file means anything.

    Also establishes r2 as the invariant reference: it is never mutated, and
    the same helper is re-run against it at the end of the suite.
    """
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    dump_neigh_state("r1", 100)
    dump_neigh_state("r1", 200)

    assert_anycast_gw_state("r1", 100)
    assert_anycast_gw_state("r1", 200)
    assert_anycast_gw_state("r2", 100)
    assert_anycast_gw_state("r2", 200)


def test_04_recreate_anycast_gateways(tgen):
    """
    Delete/recreate, mutation half: delete and re-create the anycast gateway macvlans
    on r1 with exactly the same documented configuration.  r2 is untouched
    and keeps advertising everything it knows.
    """
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # zebra re-reads the interfaces a few seconds after start up, which
    # re-adds the VNIs.  Let that settle first, so that what we test is the
    # reaction to the interface event and not a start up artefact.
    topotest.sleep(45, "waiting for the initial link re-read to settle")

    step("r1: delete and re-create both anycast gateway macvlans")
    delete_macvlan(r1, 100)
    delete_macvlan(r1, 200)

    config_macvlan(r1, 100, GW_IPS[100])
    config_macvlan(r1, 200, GW_IPS[200])

    # The re-created gateway is reachable from its directly attached hosts.
    check_ping("host11", GW_IPS[100], True, 30, 1)
    check_ping("host12", GW_IPS[200], True, 30, 1)


def test_05_remote_neigh_reinstalled(tgen):
    """
    Delete/recreate, assertion half.  The final configuration is again exactly the
    documented one, so the full baseline state must hold on the re-created
    macvlans.
    """
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    assert_anycast_gw_state("r1", 100)
    assert_anycast_gw_state("r1", 200)

    dump_neigh_state("r1", 100)
    dump_neigh_state("r1", 200)


def test_06_inter_subnet_ping_after_recreate(tgen):
    """
    Forwarding through r1 towards hosts behind r2 after the gateway
    re-provisioning, plus the local-host control case.
    """
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_ping("host11", host_ips["host22"], True, 30, 1)
    check_ping("host12", host_ips["host21"], True, 30, 1)

    check_ping("host11", host_ips["host12"], True, 30, 1)
    check_ping("host21", host_ips["host22"], True, 30, 1)


def test_07_macvlan_enslave_last(tgen):
    """
    Re-provision the anycast gateway macvlans, this time bringing
    them up *before* enslaving them into the tenant VRF - the other valid
    provisioning order, and the one ifupdown2 produces.
    """
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    delete_macvlan(r1, 100)
    delete_macvlan(r1, 200)

    config_macvlan_enslave_last(r1, 100, GW_IPS[100])
    config_macvlan_enslave_last(r1, 200, GW_IPS[200])

    assert_anycast_gw_state("r1", 100)
    assert_anycast_gw_state("r1", 200)

    check_ping("host11", host_ips["host22"], True, 30, 1)
    check_ping("host12", host_ips["host21"], True, 30, 1)


def test_08_macvlan_up_before_svi(tgen):
    """
    Bring the macvlan up while its lower device (the SVI) is still
    down, and only then bring the SVI up.

    Only VLAN 100 is mutated; VLAN 200 is asserted unchanged as the
    in-test control that nothing else moved.
    """
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("r1: take br0.100 down, re-create macvlan100 on the down SVI")
    delete_macvlan(r1, 100)
    r1.cmd_raises("ip link set dev br0.100 down")

    config_macvlan(r1, 100, GW_IPS[100])
    logger.info(
        "r1 macvlan100 while br0.100 is down:\n%s", r1.run("ip -d link show macvlan100")
    )

    step("r1: bring br0.100 up again")
    r1.cmd_raises("ip link set dev br0.100 up")

    assert_anycast_gw_state("r1", 100)
    assert_anycast_gw_state("r1", 200)

    check_ping("host11", host_ips["host21"], True, 30, 1)


def test_09_svi_carrier_cycle(tgen):
    """
    Cycle the SVI while the macvlan stays administratively up, so the
    macvlan loses and regains its lower layer.  Nothing about the anycast
    gateway may be left behind by the outage.
    """
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("r1: bounce br0.100 while macvlan100 stays admin-up")
    r1.cmd_raises("ip link set dev br0.100 down")
    logger.info(
        "r1 macvlan100 while br0.100 is down:\n%s", r1.run("ip -d link show macvlan100")
    )
    r1.cmd_raises("ip link set dev br0.100 up")

    step("r1: the macvlan keeps its address across the SVI outage")
    ok, out = _expect_shell(
        "r1",
        "ip addr show dev macvlan100",
        lambda o: GW_IPS[100] in o,
        count=30,
    )
    assert ok, f"r1: macvlan100 lost {GW_IPS[100]} across the SVI outage:\n{out}"

    assert_anycast_gw_state("r1", 100)
    assert_anycast_gw_state("r1", 200)


def test_10_macvlan_vrf_move(tgen):
    """
    Tenant-VRF move of the macvlan, which also covers the "only the macvlan
    moves, the SVI must be untouched" direction.

    Move macvlan100 from the tenant VRF into a second VRF while it is up,
    then back.  A second full L3VNI in VRF_ALT is deliberately not
    provisioned: what this scenario turns on is whether the macvlan is still
    in the same VRF as its SVI, which a second L3VNI would not change.
    """
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step(f"r1: move macvlan100 from {VRF} to {VRF_ALT} while it is up")
    before = r1.run("ip -d link show macvlan100")
    assert f"master {VRF}" in before, f"precondition failed, macvlan100 not in {VRF}"
    r1.cmd_raises(f"ip link set dev macvlan100 master {VRF_ALT}")
    after = r1.run("ip -d link show macvlan100")
    assert f"master {VRF_ALT}" in after, f"macvlan100 did not end up in {VRF_ALT}"

    step("r1: the SVI side must be entirely unaffected by the macvlan's move")
    # Positive SVI-side state first, then the negative check that no anycast
    # gateway neighbour was programmed into the foreign VRF.
    assert_anycast_gw_state("r1", 100, expect_vrr=False)
    assert_anycast_gw_state("r1", 200)

    step(f"r1: move macvlan100 back into {VRF} while it is up")
    r1.cmd_raises(f"ip link set dev macvlan100 master {VRF}")
    # the reassignment may drop the address
    r1.cmd(f"ip addr add {GW_IPS[100]}/24 dev macvlan100 brd +")
    r1.cmd_raises("ip link set dev macvlan100 up")

    assert_anycast_gw_state("r1", 100)
    assert_anycast_gw_state("r1", 200)

    check_ping("host11", host_ips["host21"], True, 30, 1)


def test_11_svi_vrf_move_macvlan_untouched(tgen):
    """
    The other move direction: move only the SVI and assert that the macvlan
    stacked on it is genuinely untouched, then move the SVI back and require
    a full recovery.

    While the SVI sits in VRF_ALT the macvlan is no longer in its SVI's VRF,
    so it is not the anycast gateway of the L2VNI any more.  That must not
    change anything about the macvlan's own configuration.
    """
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step(f"r1: move br0.100 from {VRF} to {VRF_ALT} while it is up")
    r1.cmd_raises(f"ip link set dev br0.100 master {VRF_ALT}")

    step(f"r1: zebra must follow the SVI into {VRF_ALT}")
    result = _expect_json(
        "r1",
        "show evpn vni 100 json",
        {"vni": 100, "type": "L2", "tenantVrf": VRF_ALT, "sviInterface": "br0.100"},
    )
    if result is not None:
        _dump_state("r1", "FAILED SVI move into VRF_ALT")
    assert (
        result is None
    ), f"r1: L2VNI 100 did not follow br0.100 into {VRF_ALT}: {result}"

    step("r1: macvlan100 itself must be completely untouched")
    link = r1.run("ip -d link show macvlan100")
    addr = r1.run("ip addr show dev macvlan100")
    logger.info("r1 macvlan100 while br0.100 is in %s:\n%s\n%s", VRF_ALT, link, addr)
    assert (
        f"master {VRF}" in link
    ), f"r1: macvlan100 was dragged out of {VRF} by the SVI move:\n{link}"
    assert GW_MAC in link, f"r1: macvlan100 lost its anycast MAC:\n{link}"
    assert GW_IPS[100] in addr, f"r1: macvlan100 lost its anycast address:\n{addr}"

    step("r1: VLAN 200 must be unaffected by the VLAN 100 SVI move")
    assert_anycast_gw_state("r1", 200)

    step(f"r1: move br0.100 back into {VRF}")
    r1.cmd_raises(f"ip link set dev br0.100 master {VRF}")

    assert_anycast_gw_state("r1", 100)
    assert_anycast_gw_state("r1", 200)


def test_12_second_macvlan_added_last(tgen):
    """
    Two macvlans on one SVI, anycast one created first: the tenant-VRF
    anycast gateway macvlan already exists, and a second (non-anycast,
    default-VRF) macvlan is stacked on the same SVI afterwards.  The late
    arrival must not take the anycast gateway role away from the tenant-VRF
    macvlan.
    """
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("r1: add a second, default-VRF macvlan on br0.100")
    config_second_macvlan(r1, 100)

    assert_anycast_gw_state("r1", 100)
    check_no_zebra_neigh_on_dev("r1", "macvlan100d", host_ips["host21"])

    step("r1: remove the second macvlan again")
    delete_second_macvlan(r1, 100)

    assert_anycast_gw_state("r1", 100)


def test_13_second_macvlan_added_first(tgen):
    """
    Two macvlans on one SVI, reverse order: the second macvlan is created
    before the anycast one, i.e. the non-anycast default-VRF macvlan comes
    up first and the tenant-VRF anycast gateway macvlan second.  The end
    state is identical to test_12 - same devices, same VRFs, same addresses
    - so the very same assertions must hold; only the creation order
    differs.

    This is the exotic ordering; test_12 is its conventional-order control.
    """
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("r1: rebuild the stack with the default-VRF macvlan created first")
    delete_macvlan(r1, 100)
    delete_second_macvlan(r1, 100)

    config_second_macvlan(r1, 100)
    config_macvlan(r1, 100, GW_IPS[100])

    assert_anycast_gw_state("r1", 100)
    check_no_zebra_neigh_on_dev("r1", "macvlan100d", host_ips["host21"])


def test_14_restore_baseline(tgen):
    """
    Restore the canonical topology and re-verify the full baseline on both
    routers, so that a failure above cannot be mistaken for a failure of the
    invariant reference.  r2 was never mutated and must look exactly as it
    did in test_03.
    """
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    delete_second_macvlan(r1, 100)
    delete_second_macvlan(r1, 200)
    r1.cmd("ip link del macvlan100")
    r1.cmd("ip link del macvlan200")
    r1.cmd(f"ip link set dev br0.100 master {VRF}")
    r1.cmd(f"ip link set dev br0.200 master {VRF}")
    r1.cmd_raises("ip link set dev br0.100 up")
    r1.cmd_raises("ip link set dev br0.200 up")

    config_macvlan(r1, 100, GW_IPS[100])
    config_macvlan(r1, 200, GW_IPS[200])

    assert_anycast_gw_state("r1", 100)
    assert_anycast_gw_state("r1", 200)
    # r2's view of the r1-attached hosts is derived from the type-2 routes r1
    # originates for its *local* neighbours, and a local neighbour entry ages
    # out when the host is silent.  The mutation sequence above takes long
    # enough for that to happen, so refresh with host traffic before asserting
    # the invariant reference - this is a precondition of r2's state, not a
    # relaxation of it.
    check_ping("host11", host_ips["host22"], True, 30, 1)
    check_ping("host12", host_ips["host21"], True, 30, 1)

    assert_anycast_gw_state("r2", 100)
    assert_anycast_gw_state("r2", 200)


def test_15_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

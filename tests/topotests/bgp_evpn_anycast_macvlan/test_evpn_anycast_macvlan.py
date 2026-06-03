#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_evpn_anycast_macvlan.py
#
# Copyright (c) 2026 by
# VyOS, Inc.
# Kyrylo Yatsenko
#

"""
test_evpn_anycast_macvlan.py: Testing EVPN anycast with macvlan devices

"""

import json
import os
import pytest
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
    "host1": "192.168.10.10",
    "host2": "192.168.20.10",
    "host3": "192.168.10.20",
    "host4": "192.168.20.20",
}

host_mac_map = {
    "host1": "00:50:79:66:68:01",
    "host2": "00:50:79:66:68:02",
    "host3": "00:50:79:66:68:03",
    "host4": "00:50:79:66:68:04",
}

host_vni_map = {
    "host1": "10",
    "host2": "20",
    "host3": "10",
    "host4": "20",
}

hosts = list(host_mac_map.keys())
routers = ["r1", "r2"]


def build_topo(tgen):
    """
    EVPN Anycast Topology -
    1. Two gateways: r1, r2
    2. Four hosts: host1, host2, host3, host4
        Hosts host1, host2 are connected to r1, hosts host3, host4 - to r2
        Hosts host1 and host3 are in 192.168.10.0/24 network
        Hosts host2 and host4 are in 192.168.20.0/24 network
    """

    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("host1")
    tgen.add_router("host2")
    tgen.add_router("host3")
    tgen.add_router("host4")

    # Create switches
    switch = tgen.add_switch("sr1r2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["host1"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["host2"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["host3"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["host4"])


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


def config_bridge(node):
    """
    Create a VLAN aware bridge
    """
    node.cmd_raises("ip link add dev br0 type bridge")
    node.cmd_raises("ip link set dev br0 type bridge vlan_filtering 1")
    node.cmd_raises("/sbin/bridge vlan add dev br0 vid 10 self")
    node.cmd_raises("/sbin/bridge vlan add dev br0 vid 20 self")
    node.cmd_raises("ip link set dev br0 up")
    node.cmd_raises("/sbin/bridge fdb add 00:aa:aa:aa:aa:aa dev br0 self local")


def config_interface_vid(node, ifname, vid):
    node.cmd_raises(f"ip link set dev {ifname} master br0")
    node.cmd_raises(f"/sbin/bridge link set dev {ifname} isolated off")
    node.cmd_raises(f"/sbin/bridge vlan del dev {ifname} vid 1 master")
    node.cmd_raises(
        f"/sbin/bridge vlan add dev {ifname} vid {vid} master"
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
    node.cmd_raises(f"ip link add link br0 name vlan{vid} type vlan id {vid}")
    node.cmd_raises(f"ip link set dev vlan{vid} up")
    node.cmd_raises(f"/sbin/bridge vlan add dev vxlan0 vid {vid}")
    node.cmd_raises(f"/sbin/bridge vlan add dev vxlan0 vid {vid} tunnel_info id {vid}")
    node.cmd_raises(f"sysctl -w net.ipv4.conf.vlan{vid}.arp_ignore=8")

def config_macvlan(node, vid, addr):
    node.cmd_raises(
        f"ip link add vlan{vid}agw link vlan{vid} type macvlan mode private"
    )
    node.cmd_raises(f"ip link set dev vlan{vid}agw address 00:aa:aa:aa:aa:aa")
    node.cmd_raises(f"ip addr add {addr}/24 dev vlan{vid}agw brd +")
    node.cmd_raises(f"ip link set dev vlan{vid}agw up")
    node.cmd_raises(f"/sbin/sysctl -w net.ipv4.conf.vlan{vid}agw.arp_accept=1")


def config_lo(node, lo_addr):
    node.cmd_raises(f"ip addr add {lo_addr}/32 dev lo brd +")
    node.cmd_raises("ip link set dev lo up")


def config_router(node, name, lo_addr):
    config_bridge(node)
    config_interface_vid(node, f"{name}-eth1", 10)
    config_interface_vid(node, f"{name}-eth2", 20)
    config_vxlan(node, lo_addr)
    config_vlan(node, 10)
    config_vlan(node, 20)
    config_macvlan(node, 10, "192.168.10.1")
    config_macvlan(node, 20, "192.168.20.1")
    config_lo(node, lo_addr)


def config_host(host_name, host):
    """
    Setup host with hard-coded MAC/IP
    """
    ifname = host_name + "-eth0"
    host_ip = host_ips[host_name]
    host_mac = host_mac_map[host_name]
    host_vni = host_vni_map[host_name]
    host.cmd_raises(f"ip link set dev {ifname} address {host_mac}")
    host.cmd_raises(f"ip link add link {ifname} name {ifname}.{host_vni} type vlan id {host_vni}")
    host.cmd_raises(f"ip addr add {host_ip}/24 dev {ifname}.{host_vni}")
    host.cmd_raises(f"ip link set dev {ifname}.{host_vni} up")


def config_hosts(tgen):
    for host_name in hosts:
        host = tgen.gears[host_name]
        config_host(host_name, host)


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

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


def test_ping_all_hosts(tgen):
    # check ping of all hosts to hosts
    for host1_name in hosts:
        for host2_name in hosts:
            if host1_name == host2_name:
                continue
            check_ping(host1_name, host_ips[host2_name], True, 130, 1)


def test_evpn_arp_cache(tgen):
    # Fill in arp-cache by ping
    check_ping("host1", host_ips["host4"], True, 130, 1)
    check_ping("host2", host_ips["host3"], True, 30, 1)
    # Check
    for router in routers:
        router_compare_json_output(
            router,
            "show evpn arp-cache vni all json",
            "show_evpn_arp_cache_vni_all.ref",
        )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

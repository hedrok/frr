#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 Robin Christ, partimus GmbH

"""
EVPN L2VNI SVI interface lifecycle: every ordering in which an SVI can be
brought up, moved between tenant VRFs, unslaved, recreated, or re-read from
a cold daemon start, asserted against the end state a correct FRR must show.

Operators reach the same running configuration by very different routes: a
config-management tool provisions an interface down and brings it up at the
end, an administrator on the CLI moves an interface that is already carrying
traffic, and a rebuild after an outage recreates it from scratch.  All of
these must end in the same EVPN state.  Each scenario below is one such
route, and every one of them is asserted against the end state a correct FRR
must show, never against how it got there.

Scenarios covered, and the test function covering each:

  * conventional provisioning - create the SVI, enslave it into the tenant
    VRF while it is still down, then bring it up
    -> test_02_baseline_conventional_order.  This is the reference control
    that every other scenario re-uses through assert_l2vni_state(); if it
    fails, no other verdict in this file means anything.
  * unslave an up SVI back to the default VRF ("nomaster" while up)
    -> test_03_unslave_while_up.
  * enslave an up SVI from the default VRF into a tenant VRF
    -> test_04_enslave_into_vrfa_while_up.
  * move an up SVI directly from one tenant VRF to another
    -> test_05_move_to_vrfb_while_up.
  * the same move performed the boring way, with the SVI taken down first
    -> test_06_control_move_while_down.  This is the conventional-order
    control for the two preceding scenarios and shares their assertions.
  * enslave and bring up in a single iproute2 command
    ("ip link set <svi> master <vrf> up") -> test_07_master_and_up_single_command.
  * delete the SVI and recreate it already enslaved into a tenant VRF
    -> test_12_delete_recreate_preenslaved.
  * restart zebra and bgpd while the topology stays as it is, so FRR has to
    rebuild everything from a cold read of the running system
    -> test_08_daemon_restart_cold_read.
  * the second SVI flavour - a VLAN subinterface of a VLAN-aware bridge
    rather than a bridge acting as its own SVI - put through the two
    orderings most likely to be handled differently for it
    -> test_09_vlan_aware_unslave_enslave_while_up and
    test_10_vlan_aware_move_to_vrfb_while_up, with
    test_11_vlan_aware_control_move_while_down as their control.

Pruning, so the matrix does not explode:

  * "move from one tenant VRF to another while the SVI is down" is not a
    separate test.  Once the interface is down, moving it between two tenant
    VRFs and moving it in from the default VRF are the same operation, and
    both are already performed by test_06_control_move_while_down.
  * The VLAN-aware flavour repeats only the two orderings where the two SVI
    styles could plausibly diverge - reassignment and a direct
    tenant-to-tenant move, both while the interface is up.  The remaining
    orderings are the same operator actions on a differently built SVI and
    are not duplicated.  Both flavours live in one topology, so no second
    module is needed.
  * Delete and recreate is covered only for the VLAN-aware flavour, whose
    SVI is a VLAN subinterface that can be replaced on its own.  In the
    other flavour the bridge *is* the SVI, so it cannot be deleted without
    taking the L2 domain, the vxlan device and the access port with it;
    that is a bridge teardown, a different scenario, and covering it here
    would mean asserting something other than SVI re-provisioning.
  * Changing an SVI's VRF and its MTU or MAC address in a single operation
    is not covered.  It cannot be produced as one indivisible change on a
    running system, so it is left out rather than faked with a sequence that
    would test something else.

A note on what is deliberately *not* asserted: the SVI's MAC address is
never checked for stability across a VRF move, because it is allowed to
change; and state that is still present in the previous tenant VRF is not
treated as stale on sight, because a route can legitimately be there by
route-target import from the unmutated peer.

Topology (symmetric IRB, two VTEPs, one link):

    +-----+ eth-pe2      10.0.12.0/24      eth-pe1 +-----+
    | pe1 |------------------------------------------| pe2 |
    +-----+                                          +-----+

  Both PEs:
      vrfA (table 10) -- L3VNI 10 -- brA   + vniA
      vrfB (table 20) -- L3VNI 20 -- brB   + vniB
      L2VNI 100       -- br100 (a plain bridge acting as its own SVI)
                         + vni100 + d100 (access port)
      L2VNI 200       -- br200 (VLAN-aware) with SVI br200.200
                         + vni200 + d200 (access port)

  pe2 keeps both SVIs in vrfA for the whole run and holds static fdb and
  neighbour entries for one emulated host per L2VNI.  It therefore
  originates the type-2 routes pe1 has to program, and its own state is
  invariant: every scenario re-checks it, which catches accidental
  withdraw/re-advertise storms triggered by pe1's mutations.

  All mutations happen on pe1.
"""

import functools
import json as jsonlib
import os
import platform
import re
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import kill_router_daemons, start_router_daemons, step
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

L3VNI_A = 10
L3VNI_B = 20
VRF_A = "vrfA"
VRF_B = "vrfB"
DEFAULT_VRF = "default"

PE1_VTEP = "10.0.12.1"
PE2_VTEP = "10.0.12.2"

# Per L2VNI: the SVI and its flavour, the vxlan device, the access port, the
# subnet, and the host pe2 emulates on it.
VNI_INFO = {
    100: {
        "svi": "br100",
        "bridge": "br100",
        "vxlan": "vni100",
        "port": "d100",
        "subnet": "192.168.100.0/24",
        "svi_ip": "192.168.100.254/24",
        "host_ip": "192.168.100.2",
        "host_mac": "02:00:00:00:01:02",
        "vlan_aware": False,
    },
    200: {
        "svi": "br200.200",
        "bridge": "br200",
        "vxlan": "vni200",
        "port": "d200",
        "subnet": "192.168.200.0/24",
        "svi_ip": "192.168.200.254/24",
        "host_ip": "192.168.200.2",
        "host_mac": "02:00:00:00:02:02",
        "vlan_aware": True,
    },
}

L2VNIS = sorted(VNI_INFO)


def build_topo(tgen):
    tgen.add_router("pe1")
    tgen.add_router("pe2")

    switch = tgen.add_switch("s-pe1-pe2")
    switch.add_link(tgen.gears["pe1"], nodeif="eth-pe2")
    switch.add_link(tgen.gears["pe2"], nodeif="eth-pe1")


def _run_cmds(node, commands):
    for command in commands:
        node.cmd_raises(command)


def _l3vni_commands(vtep, peer_if):
    """The two tenant VRFs and their L3VNIs.  These never move."""
    return [
        "ip link add up vrfA type vrf table 10",
        "ip link add up vrfB type vrf table 20",
        "ip link add brA type bridge",
        "ip link set brA master vrfA",
        "ip link set brA up",
        f"ip link add up vniA type vxlan id {L3VNI_A} local {vtep} dev {peer_if}"
        " nolearning dstport 4789",
        "ip link set vniA master brA",
        "bridge link set dev vniA learning off",
        "ip link add brB type bridge",
        "ip link set brB master vrfB",
        "ip link set brB up",
        f"ip link add up vniB type vxlan id {L3VNI_B} local {vtep} dev {peer_if}"
        " nolearning dstport 4789",
        "ip link set vniB master brB",
        "bridge link set dev vniB learning off",
    ]


def _l2vni_100_commands(vtep, peer_if):
    """
    L2VNI 100: a plain (not VLAN-aware) bridge that is its own SVI.

    Provisioned in the conventional order - create, enslave into the tenant
    VRF while still down, then up - which is the reference control ordering.
    """
    info = VNI_INFO[100]
    return [
        f"ip link add {info['bridge']} type bridge",
        f"ip link set {info['bridge']} master {VRF_A}",
        f"ip link set {info['bridge']} up",
        f"ip address add {info['svi_ip']} dev {info['svi']}",
        f"ip link add up {info['vxlan']} type vxlan id 100 local {vtep} dev {peer_if}"
        " nolearning dstport 4789",
        f"ip link set {info['vxlan']} master {info['bridge']}",
        f"bridge link set dev {info['vxlan']} learning off",
        f"ip link add {info['port']} type dummy",
        f"ip link set {info['port']} master {info['bridge']}",
        f"ip link set {info['port']} up",
    ]


def _l2vni_200_commands(vtep, peer_if):
    """
    L2VNI 200: a VLAN-aware bridge whose SVI is the VLAN subinterface
    br200.200 - the second of the two common ways to build an SVI, and a
    different device layout from the bridge-as-SVI flavour above.
    """
    info = VNI_INFO[200]
    return [
        f"ip link add {info['bridge']} type bridge",
        # vlan_default_pvid 0 keeps VLAN 1 off every port, so each port
        # carries exactly VLAN 200 and the vxlan-to-VLAN mapping of the
        # bridge is unambiguous.
        f"ip link set {info['bridge']} type bridge vlan_filtering 1"
        " vlan_default_pvid 0",
        f"ip link set {info['bridge']} up",
        f"bridge vlan add dev {info['bridge']} vid 200 self",
        f"ip link add up {info['vxlan']} type vxlan id 200 local {vtep} dev {peer_if}"
        " nolearning dstport 4789",
        f"ip link set {info['vxlan']} master {info['bridge']}",
        f"bridge link set dev {info['vxlan']} learning off",
        f"bridge vlan add dev {info['vxlan']} vid 200 pvid untagged",
        f"ip link add {info['port']} type dummy",
        f"ip link set {info['port']} master {info['bridge']}",
        f"ip link set {info['port']} up",
        f"bridge vlan add dev {info['port']} vid 200 pvid untagged",
        # the SVI, again in the conventional order
        f"ip link add link {info['bridge']} name {info['svi']} type vlan id 200",
        f"ip link set {info['svi']} master {VRF_A}",
        f"ip link set {info['svi']} up",
        f"ip address add {info['svi_ip']} dev {info['svi']}",
    ]


def _emulated_host_commands():
    """
    Static local state on pe2 for one host per L2VNI.  pe2 originates the
    type-2 routes from these; no real host node is needed and pe2's view
    stays constant while pe1 is mutated.
    """
    commands = []
    for vni in L2VNIS:
        info = VNI_INFO[vni]
        vlan = " vlan 200" if info["vlan_aware"] else ""
        commands.append(
            f"bridge fdb add {info['host_mac']} dev {info['port']} master static{vlan}"
        )
        commands.append(
            f"ip neigh add {info['host_ip']} lladdr {info['host_mac']}"
            f" dev {info['svi']} nud permanent"
        )
    return commands


def _setup_pe(router, idx):
    vtep = PE1_VTEP if idx == 1 else PE2_VTEP
    peer_if = "eth-pe2" if idx == 1 else "eth-pe1"

    _run_cmds(router, _l3vni_commands(vtep, peer_if))
    _run_cmds(router, _l2vni_100_commands(vtep, peer_if))
    _run_cmds(router, _l2vni_200_commands(vtep, peer_if))

    if idx == 2:
        _run_cmds(router, _emulated_host_commands())


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.18") < 0:
        pytest.skip(
            f'Skipping EVPN SVI lifecycle test, kernel "{krel}" is too old',
            allow_module_level=True,
        )

    for idx in (1, 2):
        _setup_pe(tgen.gears[f"pe{idx}"], idx)

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


#####################################################
##
##   Helpers
##
#####################################################


def _vtysh_json(pe, cmd):
    return jsonlib.loads(get_topogen().gears[pe].vtysh_cmd(cmd))


def _expect_json(pe, cmd, expected, count=60, wait=1):
    router = get_topogen().gears[pe]
    test_func = functools.partial(topotest.router_json_cmp, router, cmd, expected)
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    return result


def _expect_shell(pe, cmd, matcher, count=60, wait=1):
    """Poll a shell command until matcher(output) is True.  Returns (ok, output)."""
    router = get_topogen().gears[pe]
    state = {"out": ""}

    def _check():
        state["out"] = router.cmd(cmd)
        return matcher(state["out"])

    _, ok = topotest.run_and_expect(_check, True, count=count, wait=wait)
    return ok, state["out"]


def _zebra_l3vni_l2vnis(pe, l3vni):
    return _vtysh_json(pe, f"show evpn vni {l3vni} json").get("l2Vnis", [])


def _bgp_l3vni_l2vnis(pe, l3vni):
    return _vtysh_json(pe, f"show bgp l2vpn evpn vni {l3vni} json").get("l2Vnis", [])


def _route_show_cmd(tenant_vrf):
    if tenant_vrf == DEFAULT_VRF:
        return "ip route show"
    return f"ip route show vrf {tenant_vrf}"


def _dump_state(pe, tag):
    """Evidence for debugging only - never an input to a verdict."""
    router = get_topogen().gears[pe]
    logger.info("=========== %s : %s ===========", pe, tag)
    for cmd in (
        "show evpn vni json",
        "show evpn vni 100 json",
        "show evpn vni 200 json",
        f"show evpn vni {L3VNI_A} json",
        f"show evpn vni {L3VNI_B} json",
        "show evpn mac vni all json",
        "show evpn arp-cache vni all json",
        f"show bgp l2vpn evpn vni {L3VNI_A} json",
        f"show bgp l2vpn evpn vni {L3VNI_B} json",
    ):
        logger.info("--- vtysh %s\n%s", cmd, router.vtysh_cmd(cmd))
    for cmd in (
        "ip -d link show",
        "ip addr show",
        "ip neigh show",
        "bridge fdb show dev vni100",
        "bridge fdb show dev vni200",
        f"ip route show vrf {VRF_A}",
        f"ip route show vrf {VRF_B}",
        "ip route show",
    ):
        logger.info("--- shell %s\n%s", cmd, router.cmd(cmd))


def assert_l2vni_state(pe, vni, tenant_vrf, count=60):
    """
    The one shared end-state assertion for an L2VNI.  Every scenario and
    every control goes through it; nothing duplicates its checks.

      pe          - "pe1" or "pe2"
      vni         - 100 (bridge-as-SVI) or 200 (VLAN-aware bridge SVI)
      tenant_vrf  - the VRF the SVI is expected to be in, or "default".
                    L3VNI membership is asserted positively for the matching
                    L3VNI and negatively for the other one, in both zebra and
                    bgpd; with "default" neither L3VNI may claim the L2VNI.

    Exact numMacs/numArpNd counts are deliberately not asserted - they would
    only encode how many entries happen to be cached.  The specific expected
    entries are asserted instead.
    """
    info = VNI_INFO[vni]
    svi = info["svi"]
    host_ip = info["host_ip"]
    host_mac = info["host_mac"]
    peer_vtep = PE2_VTEP if pe == "pe1" else PE1_VTEP

    # --- zebra: the VNI itself -------------------------------------------
    step(f"{pe}: zebra must report L2VNI {vni} in {tenant_vrf} on {svi}")
    expected = {
        "vni": vni,
        "type": "L2",
        "tenantVrf": tenant_vrf,
        "sviInterface": svi,
        "vxlanInterface": info["vxlan"],
    }
    result = _expect_json(pe, f"show evpn vni {vni} json", expected, count=count)
    if result is not None:
        _dump_state(pe, f"FAILED vni state, vni {vni}")
    assert result is None, (
        f"{pe}: L2VNI {vni} state wrong (expected tenant VRF {tenant_vrf}, "
        f"SVI {svi}): {result}"
    )

    # --- zebra: the remote MAC and neighbour -----------------------------
    step(f"{pe}: zebra must know {host_mac} as remote in L2VNI {vni}")
    expected = {"macs": {host_mac: {"type": "remote", "remoteVtep": peer_vtep}}}
    result = _expect_json(pe, f"show evpn mac vni {vni} json", expected, count=count)
    assert result is None, f"{pe}: remote MAC {host_mac} missing in VNI {vni}: {result}"

    step(f"{pe}: zebra must know {host_ip} as remote neighbour in L2VNI {vni}")
    expected = {host_ip: {"type": "remote", "mac": host_mac}}
    result = _expect_json(
        pe, f"show evpn arp-cache vni {vni} json", expected, count=count
    )
    assert result is None, f"{pe}: remote neighbour {host_ip} missing: {result}"

    # --- zebra and bgpd: L2VNI to L3VNI association ----------------------
    # The expected-present L3VNI is checked first and the expected-absent one
    # second, so a stale reference is only reported once the new association
    # has converged; checking for absence first races against the transient.
    associations = [(L3VNI_A, tenant_vrf == VRF_A), (L3VNI_B, tenant_vrf == VRF_B)]
    associations.sort(key=lambda entry: not entry[1])

    for l3vni, want in associations:
        step(f"{pe}: zebra L3VNI {l3vni} must {'' if want else 'not '}list L2VNI {vni}")
        _, ok = topotest.run_and_expect(
            lambda l3vni=l3vni, want=want: (vni in _zebra_l3vni_l2vnis(pe, l3vni))
            == want,
            True,
            count=30,
            wait=1,
        )
        assert ok, (
            f"{pe}: zebra L3VNI {l3vni} l2Vnis={_zebra_l3vni_l2vnis(pe, l3vni)}, "
            f"expected L2VNI {vni} {'present' if want else 'absent'}"
        )

        step(f"{pe}: bgpd L3VNI {l3vni} must {'' if want else 'not '}list L2VNI {vni}")
        _, ok = topotest.run_and_expect(
            lambda l3vni=l3vni, want=want: (vni in _bgp_l3vni_l2vnis(pe, l3vni))
            == want,
            True,
            count=30,
            wait=1,
        )
        assert ok, (
            f"{pe}: bgpd L3VNI {l3vni} l2Vnis={_bgp_l3vni_l2vnis(pe, l3vni)}, "
            f"expected L2VNI {vni} {'present' if want else 'absent'}"
        )

    # --- forwarding state: the remote MAC on the vxlan device ------------
    step(f"{pe}: the fdb of {info['vxlan']} must hold {host_mac} via {peer_vtep}")
    ok, out = _expect_shell(
        pe,
        f"bridge fdb show dev {info['vxlan']}",
        lambda o: re.search(rf"{host_mac}.*dst {re.escape(peer_vtep)}", o) is not None,
        count=count,
    )
    assert ok, f"{pe}: fdb of {info['vxlan']} missing remote MAC {host_mac}:\n{out}"

    # --- forwarding state: the remote neighbour on the SVI ---------------
    # This is the check that catches an SVI that survived the operation with
    # an empty neighbour table: the routes are still there, but traffic to
    # the remote host would be dropped.
    step(f"{pe}: {host_ip} must be reinstalled on {svi} as an external entry")
    ok, out = _expect_shell(
        pe,
        f"ip neigh show dev {svi}",
        lambda o: re.search(rf"{host_ip} +lladdr {host_mac}.*extern_learn", o)
        is not None,
        count=count,
    )
    assert (
        ok
    ), f"{pe}: remote neighbour {host_ip} not installed by zebra on {svi}:\n{out}"

    # --- forwarding state: the connected subnet in the right table -------
    step(f"{pe}: {info['subnet']} must be connected via {svi} in {tenant_vrf}")
    ok, out = _expect_shell(
        pe,
        _route_show_cmd(tenant_vrf),
        lambda o: re.search(rf"{re.escape(info['subnet'])} dev {svi}\b", o) is not None,
        count=count,
    )
    assert ok, (
        f"{pe}: connected route {info['subnet']} via {svi} missing from "
        f"{tenant_vrf}:\n{out}"
    )


def assert_reference_pe2_unchanged():
    """
    pe2 is never mutated.  Both its L2VNIs must stay in vrfA with their
    emulated hosts local, which catches a mutation on pe1 that triggers a
    withdraw/re-advertise storm or otherwise disturbs the peer.
    """
    for vni in L2VNIS:
        info = VNI_INFO[vni]
        step(f"pe2 (invariant reference): L2VNI {vni} must be unchanged")
        expected = {
            "vni": vni,
            "type": "L2",
            "tenantVrf": VRF_A,
            "sviInterface": info["svi"],
        }
        result = _expect_json("pe2", f"show evpn vni {vni} json", expected)
        assert result is None, f"pe2: L2VNI {vni} changed: {result}"

        expected = {"macs": {info["host_mac"]: {"type": "local"}}}
        result = _expect_json("pe2", f"show evpn mac vni {vni} json", expected)
        assert result is None, (
            f"pe2: emulated host MAC {info['host_mac']} is no longer local in "
            f"VNI {vni}: {result}"
        )


def _svi_master(pe, svi):
    """The VRF the SVI is currently in, or 'default'."""
    out = get_topogen().gears[pe].cmd(f"ip -d link show {svi}")
    match = re.search(r"master (\S+)", out)
    return match.group(1) if match else DEFAULT_VRF


def assert_svi_vrf(pe, svi, expected_vrf):
    """Guard that the operation under test actually took effect."""
    actual = _svi_master(pe, svi)
    assert (
        actual == expected_vrf
    ), f"{pe}: {svi} is in {actual}, expected {expected_vrf}"


def readd_svi_address(pe, vni):
    """
    Re-add the SVI address after an operation that may have dropped it.
    Whether the address survives a given reassignment is not what any of
    these scenarios is about, so it is simply restored.
    """
    info = VNI_INFO[vni]
    get_topogen().gears[pe].cmd(f"ip address add {info['svi_ip']} dev {info['svi']}")


def baseline(vni, tenant_vrf):
    """Verify the full working state before mutating it."""
    step(f"BASELINE: L2VNI {vni} fully converged in {tenant_vrf}")
    assert_l2vni_state("pe1", vni, tenant_vrf)


def _no_router_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    return tgen


#####################################################
##
##   Tests
##
#####################################################


def test_01_baseline_bgp_session():
    tgen = _no_router_failure()

    step("Wait for the EVPN session between pe1 and pe2")
    expected = {"peers": {PE2_VTEP: {"state": "Established"}}}
    result = _expect_json("pe1", "show bgp l2vpn evpn summary json", expected)
    assert result is None, f"pe1 EVPN session with pe2 did not come up: {result}"


def test_02_baseline_conventional_order():
    """
    The reference control: both SVIs were created, enslaved into vrfA while
    still down, and only then brought up.  This is what a config-management
    tool produces and the order documented for most deployments, so it is
    the ordering FRR is most expected to get right.

    Every later scenario re-uses assert_l2vni_state() unchanged, so if this
    test fails the assertions themselves are wrong.
    """
    _no_router_failure()

    for vni in L2VNIS:
        assert_l2vni_state("pe1", vni, VRF_A)

    assert_reference_pe2_unchanged()
    _dump_state("pe1", "baseline, both SVIs in vrfA")


def test_03_unslave_while_up():
    """
    Unslave the bridge-as-SVI back to the default VRF while it is up.

    This is what an operator does when a tenant is being decommissioned but
    the L2 domain has to keep working.

    Correct end state: the L2VNI falls back to the default VRF cleanly,
    neither tenant VRF's L3VNI keeps a reference to it, and the remote
    neighbour is still reachable through the SVI.
    """
    tgen = _no_router_failure()
    pe1 = tgen.gears["pe1"]
    svi = VNI_INFO[100]["svi"]

    baseline(100, VRF_A)

    step(f"pe1: unslave {svi} while it is up")
    assert_svi_vrf("pe1", svi, VRF_A)
    pe1.cmd_raises(f"ip link set {svi} nomaster")
    readd_svi_address("pe1", 100)
    assert_svi_vrf("pe1", svi, DEFAULT_VRF)

    assert_l2vni_state("pe1", 100, DEFAULT_VRF)

    step("pe1: the untouched L2VNI 200 must be unaffected")
    assert_l2vni_state("pe1", 200, VRF_A)
    assert_reference_pe2_unchanged()


def test_04_enslave_into_vrfa_while_up():
    """
    Enslave the bridge-as-SVI from the default VRF into vrfA while it is up,
    the reverse of the previous scenario and the ordering a manual
    "ip link set" session produces.

    Correct end state: identical to conventional provisioning into vrfA -
    the ordering must not matter.
    """
    tgen = _no_router_failure()
    pe1 = tgen.gears["pe1"]
    svi = VNI_INFO[100]["svi"]

    baseline(100, DEFAULT_VRF)

    step(f"pe1: enslave {svi} into {VRF_A} while it is up")
    pe1.cmd_raises(f"ip link set {svi} master {VRF_A}")
    readd_svi_address("pe1", 100)
    assert_svi_vrf("pe1", svi, VRF_A)

    assert_l2vni_state("pe1", 100, VRF_A)
    assert_reference_pe2_unchanged()


def test_05_move_to_vrfb_while_up():
    """
    Move the bridge-as-SVI directly from vrfA to vrfB while it is up.

    This is the live re-homing of a tenant network, done without taking the
    interface out of service first.

    Correct end state: the L2VNI is associated with vrfB's L3VNI in both
    zebra and bgpd, vrfA's L3VNI no longer references it, and the remote
    neighbour is reinstalled on the SVI.
    """
    tgen = _no_router_failure()
    pe1 = tgen.gears["pe1"]
    svi = VNI_INFO[100]["svi"]

    baseline(100, VRF_A)

    step(f"pe1: move {svi} from {VRF_A} to {VRF_B} while it is up")
    pe1.cmd_raises(f"ip link set {svi} master {VRF_B}")
    readd_svi_address("pe1", 100)
    assert_svi_vrf("pe1", svi, VRF_B)

    assert_l2vni_state("pe1", 100, VRF_B)

    step("pe1: the untouched L2VNI 200 must still be in vrfA")
    assert_l2vni_state("pe1", 200, VRF_A)
    assert_reference_pe2_unchanged()


def test_06_control_move_while_down():
    """
    The conventional-order control for the two preceding scenarios: the very
    same vrfB-to-vrfA move, but with the SVI taken down first and brought up
    afterwards.  Same end state, same assertions.

    This also stands in for "move between tenant VRFs while down": with the
    interface down, moving it between two tenant VRFs and moving it in from
    the default VRF are the same operation.

    If this control fails, the assertions are wrong rather than the exotic
    orderings being broken.
    """
    tgen = _no_router_failure()
    pe1 = tgen.gears["pe1"]
    svi = VNI_INFO[100]["svi"]

    baseline(100, VRF_B)

    step(f"pe1: down, enslave into {VRF_A}, up - the boring order")
    pe1.cmd_raises(f"ip link set {svi} down")
    pe1.cmd_raises(f"ip link set {svi} master {VRF_A}")
    pe1.cmd_raises(f"ip link set {svi} up")
    readd_svi_address("pe1", 100)
    assert_svi_vrf("pe1", svi, VRF_A)

    assert_l2vni_state("pe1", 100, VRF_A)
    assert_reference_pe2_unchanged()


def test_07_master_and_up_single_command():
    """
    Enslave and bring up in one iproute2 command, starting from a down SVI:
    "ip link set <svi> master vrfB up".

    Operators and scripts write it this way all the time, and it must be
    equivalent to issuing the two settings one after the other.
    """
    tgen = _no_router_failure()
    pe1 = tgen.gears["pe1"]
    svi = VNI_INFO[100]["svi"]

    baseline(100, VRF_A)

    step(f"pe1: take {svi} down, then enslave into {VRF_B} and up in one command")
    pe1.cmd_raises(f"ip link set {svi} down")
    pe1.cmd_raises(f"ip link set {svi} master {VRF_B} up")
    readd_svi_address("pe1", 100)
    assert_svi_vrf("pe1", svi, VRF_B)

    assert_l2vni_state("pe1", 100, VRF_B)
    assert_reference_pe2_unchanged()


def test_08_daemon_restart_cold_read():
    """
    Restart zebra and bgpd on pe1 on top of the topology the scenarios above
    left behind, the way a package upgrade or a daemon crash would.  FRR has
    to rebuild its whole EVPN view by reading the running system from
    scratch, and must converge on exactly the same end state it had before.

    Nothing about the topology is changed here; it is the input, not the
    subject.
    """
    tgen = _no_router_failure()

    expected_vrfs = {100: VRF_B, 200: VRF_A}
    for vni in L2VNIS:
        baseline(vni, expected_vrfs[vni])

    step("pe1: restart zebra and bgpd")
    kill_router_daemons(tgen, "pe1", ["bgpd", "zebra"], save_config=False)
    start_router_daemons(tgen, "pe1", ["zebra", "bgpd"])

    step("pe1: the EVPN session must come back up")
    expected = {"peers": {PE2_VTEP: {"state": "Established"}}}
    result = _expect_json("pe1", "show bgp l2vpn evpn summary json", expected)
    assert result is None, f"pe1 EVPN session did not recover after restart: {result}"

    for vni in L2VNIS:
        assert_l2vni_state("pe1", vni, expected_vrfs[vni])

    assert_reference_pe2_unchanged()


def test_09_vlan_aware_unslave_enslave_while_up():
    """
    The second SVI flavour: br200.200, a VLAN subinterface of a VLAN-aware
    bridge.  This is the layout most vendors' documentation uses for
    multi-VLAN access switches, and it is built differently enough from a
    bridge acting as its own SVI to be worth repeating the orderings on.

    Here: unslave to the default VRF while up, then enslave back into vrfA
    while up.

    The bridge underneath is not part of the operation and must come out of
    it untouched, which is asserted explicitly below.
    """
    tgen = _no_router_failure()
    pe1 = tgen.gears["pe1"]
    info = VNI_INFO[200]
    svi = info["svi"]

    baseline(200, VRF_A)

    step(f"pe1: unslave {svi} while it is up")
    pe1.cmd_raises(f"ip link set {svi} nomaster")
    readd_svi_address("pe1", 200)
    assert_svi_vrf("pe1", svi, DEFAULT_VRF)

    assert_l2vni_state("pe1", 200, DEFAULT_VRF)

    step("pe1: the bridge underneath must not have been dragged anywhere")
    assert_svi_vrf("pe1", info["bridge"], DEFAULT_VRF)

    step(f"pe1: enslave {svi} back into {VRF_A} while it is up")
    pe1.cmd_raises(f"ip link set {svi} master {VRF_A}")
    readd_svi_address("pe1", 200)
    assert_svi_vrf("pe1", svi, VRF_A)

    assert_l2vni_state("pe1", 200, VRF_A)

    # L2VNI 100 was left in vrfB by the earlier scenarios and must not have
    # been disturbed by anything done to the other SVI.
    step("pe1: the untouched L2VNI 100 must be unaffected")
    assert_l2vni_state("pe1", 100, VRF_B)
    assert_reference_pe2_unchanged()


def test_10_vlan_aware_move_to_vrfb_while_up():
    """
    The VLAN-aware flavour moved directly from vrfA to vrfB while up.

    Same live re-homing as for the bridge-as-SVI flavour, and it must reach
    the same end state.
    """
    tgen = _no_router_failure()
    pe1 = tgen.gears["pe1"]
    svi = VNI_INFO[200]["svi"]

    baseline(200, VRF_A)

    step(f"pe1: move {svi} from {VRF_A} to {VRF_B} while it is up")
    pe1.cmd_raises(f"ip link set {svi} master {VRF_B}")
    readd_svi_address("pe1", 200)
    assert_svi_vrf("pe1", svi, VRF_B)

    assert_l2vni_state("pe1", 200, VRF_B)

    step("pe1: the untouched L2VNI 100 must still be where it was")
    assert_l2vni_state("pe1", 100, VRF_B)
    assert_reference_pe2_unchanged()


def test_11_vlan_aware_control_move_while_down():
    """
    The conventional-order control for the two VLAN-aware scenarios: the
    same vrfB-to-vrfA move done with the SVI down first, reaching the same
    end state through the same assertions.
    """
    tgen = _no_router_failure()
    pe1 = tgen.gears["pe1"]
    svi = VNI_INFO[200]["svi"]

    baseline(200, VRF_B)

    step(f"pe1: down, enslave into {VRF_A}, up - the boring order")
    pe1.cmd_raises(f"ip link set {svi} down")
    pe1.cmd_raises(f"ip link set {svi} master {VRF_A}")
    pe1.cmd_raises(f"ip link set {svi} up")
    readd_svi_address("pe1", 200)
    assert_svi_vrf("pe1", svi, VRF_A)

    assert_l2vni_state("pe1", 200, VRF_A)
    assert_reference_pe2_unchanged()


def test_12_delete_recreate_preenslaved():
    """
    Delete the SVI and recreate it already enslaved into the other tenant
    VRF, without touching anything underneath it.  The bridge, the vxlan
    device and the access port all stay up and in service for the whole
    operation; only the routed interface is replaced.

    This is what re-addressing or re-homing a tenant SVI looks like in
    practice, and it is the one shape where the interface never exists
    outside a VRF at any point.

    Only the VLAN-aware flavour is covered here.  In the other flavour the
    bridge *is* the SVI, so there is no SVI to delete on its own: removing
    it would take the whole L2 domain, the vxlan device and the access port
    down with it, which is a bridge teardown rather than an SVI
    re-provisioning and would be testing something else.

    The recreated interface starts out with nothing on it, so every entry
    visible afterwards is one FRR put back.
    """
    tgen = _no_router_failure()
    pe1 = tgen.gears["pe1"]
    info = VNI_INFO[200]

    baseline(200, VRF_A)

    step(f"pe1: delete {info['svi']} and recreate it pre-enslaved into {VRF_B}")
    pe1.cmd_raises(f"ip link del {info['svi']}")
    _run_cmds(
        pe1,
        [
            f"ip link add link {info['bridge']} name {info['svi']} master {VRF_B}"
            " type vlan id 200",
            f"ip link set {info['svi']} up",
            f"ip address add {info['svi_ip']} dev {info['svi']}",
        ],
    )
    assert_svi_vrf("pe1", info["svi"], VRF_B)

    step("pe1: the bridge underneath must have stayed in service throughout")
    for dev in (info["bridge"], info["vxlan"], info["port"]):
        out = pe1.cmd(f"ip -d link show {dev}")
        assert (
            re.search(r"<[^>]*\bUP\b[^>]*>", out) is not None
        ), f"pe1: {dev} did not stay up across the SVI recreate:\n{out}"

    assert_l2vni_state("pe1", 200, VRF_B)

    step("pe1: the untouched L2VNI 100 must be unaffected")
    assert_l2vni_state("pe1", 100, VRF_B)
    assert_reference_pe2_unchanged()


def test_13_restore_and_reverify():
    """
    Put both SVIs back into vrfA the conventional way and re-verify the full
    baseline, so a failure above cannot be confused with a broken reference.
    """
    tgen = _no_router_failure()
    pe1 = tgen.gears["pe1"]

    for vni in L2VNIS:
        svi = VNI_INFO[vni]["svi"]
        step(f"pe1: return {svi} to {VRF_A}")
        pe1.cmd_raises(f"ip link set {svi} down")
        pe1.cmd_raises(f"ip link set {svi} master {VRF_A}")
        pe1.cmd_raises(f"ip link set {svi} up")
        readd_svi_address("pe1", vni)
        assert_svi_vrf("pe1", svi, VRF_A)

    for vni in L2VNIS:
        assert_l2vni_state("pe1", vni, VRF_A)

    assert_reference_pe2_unchanged()
    _dump_state("pe1", "final state, both SVIs back in vrfA")


def test_14_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

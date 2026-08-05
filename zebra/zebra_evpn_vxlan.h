// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra EVPN for VxLAN code
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
 */

/* Get the VRR interface for SVI if any. The association is authoritative:
 * it is re-elected on every event that can change it, so a non-NULL value
 * is a macvlan stacked on the SVI in the SVI's own VRF.
 */
static inline struct interface *zebra_get_vrr_intf_for_svi(struct interface *ifp)
{
	struct zebra_if *zif = ifp->info;

	return zif ? zif->vrr_if : NULL;
}

/* EVPN<=>vxlan_zif association */
static inline void zevpn_vxlan_if_set(struct zebra_evpn *zevpn,
				      struct interface *ifp, bool set)
{
	struct zebra_if *zif;

	if (set) {
		if (zevpn->vxlan_if == ifp)
			return;
		zevpn->vxlan_if = ifp;
	} else {
		if (!zevpn->vxlan_if)
			return;
		zevpn->vxlan_if = NULL;
	}

	if (ifp)
		zif = ifp->info;
	else
		zif = NULL;

	zebra_evpn_vxl_evpn_set(zif, zevpn, set);
}

/* EVPN<=>Bridge interface association */
static inline void zevpn_bridge_if_set(struct zebra_evpn *zevpn,
				       struct interface *ifp, bool set)
{
	if (set) {
		if (zevpn->bridge_if == ifp)
			return;
		zevpn->bridge_if = ifp;
	} else {
		if (!zevpn->bridge_if)
			return;
		zevpn->bridge_if = NULL;
	}
}

/* EVPN<=>Bridge interface association */
static inline void zl3vni_bridge_if_set(struct zebra_l3vni *zl3vni,
					struct interface *ifp, bool set)
{
	if (set) {
		if (zl3vni->bridge_if == ifp)
			return;
		zl3vni->bridge_if = ifp;
	} else {
		if (!zl3vni->bridge_if)
			return;
		zl3vni->bridge_if = NULL;
	}
}

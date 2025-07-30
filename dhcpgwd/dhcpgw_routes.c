// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DHCP gateway related functions
 * Copyright (C) 2025 VyOS Inc.
 * Kyrylo Yatsenko
 */

#include "dhcpgwd/dhcpgw_routes.h"

#include "dhcpgwd/dhcpgw_state.h"

#include "dhcpgwd/dhcpgw_vty.h"

DEFINE_MGROUP(DHCPGW, "dhcp-gateway");

DEFINE_MTYPE_STATIC(DHCPGW, DHCPGW_ROUTE, "DHCP Gateway Route");
DEFINE_MTYPE_STATIC(DHCPGW, DHCPGW_INTERFACE, "DHCP Gateway Interface");

/*
 * List of routes
 */
PREDECL_LIST(dhcpgw_route_list);

struct dhcpgw_route {
	/* For linked list. */
	struct dhcpgw_route_list_item list;

	int af;
	char *command_prefix;
	char *command_suffix;
};

DECLARE_LIST(dhcpgw_route_list, struct dhcpgw_route, list);

/*
 * List of interfaces used by routes
 */
PREDECL_SORTLIST_UNIQ(dhcpgw_interface_list);

struct dhcpgw_interface {
	/* For linked list. */
	struct dhcpgw_interface_list_item list;

	char ifname[IFNAMSIZ + 1];              /* Main key of item - which interface is watched */
	bool last_up;                           /* Last stored is interface up */
	int last_af;                            /* Last stored address family */
	char last_ip_str[INET6_ADDRSTRLEN];     /* Last stored address for interface */

	/* list of dhcp-gateway routes for this interface */
	struct dhcpgw_route_list_head routes_head;
};

static int cmp_dhcpgw_interface(const struct dhcpgw_interface *a,
		const struct dhcpgw_interface *b)
{
	zlog_notice("%s: comparing '%s' and '%s', result: %d", __func__, a->ifname, b->ifname, strcmp(a->ifname, b->ifname));
	return strcmp(a->ifname, b->ifname);
}

DECLARE_SORTLIST_UNIQ(dhcpgw_interface_list, struct dhcpgw_interface, list,
		cmp_dhcpgw_interface);

/* List of interfaces */
static struct dhcpgw_interface_list_head interfaces_list_head;

/* Free dhcpgw interface memory and memory of all routes */
static void dhcpgw_interface_free(struct dhcpgw_interface *dgif);
/* Free resources of one dhcpgw route */
static void dhcpgw_route_free(struct dhcpgw_route *dgrt);

/* Get dhcpgw_interface by ifname, NULL if not found */
static struct dhcpgw_interface* dhcpgw_routes_find_interface(const char* ifname);
/* Get dhcpgw_interface by ifname. If doesn't exist - create, read real data */
static struct dhcpgw_interface* dhcpgw_routes_find_or_create_interface(const char* ifname);
/* Find route with same command_prefix and command_suffix in interface's list, NULL if not found */
static struct dhcpgw_route* dhcpgw_routes_find_route(struct dhcpgw_interface *dgif,
		const char* command_prefix, const char* command_suffix);
/* Delete route from staticd, delete from list, free */
static void dhcpgw_route_delete(struct dhcpgw_interface* dgif, struct dhcpgw_route* dgrt);
/* Allocate, add to list, install route in staticd */
static void dhcpgw_route_add(struct dhcpgw_interface* dgif, int af, const char*
		command_prefix, const char* command_suffix);

/* Add route to or remove route from staticd */
static void staticd_route_change_enqueue(bool no, struct dhcpgw_interface* dgif, struct dhcpgw_route *dgrt);

/* IMPLEMENTATION */

static void dhcpgw_interface_free(struct dhcpgw_interface *dgif)
{
	struct dhcpgw_route *dgrt;

	while ((dgrt = dhcpgw_route_list_pop(&dgif->routes_head))) {
		staticd_route_change_enqueue(true, dgif, dgrt);
		dhcpgw_route_free(dgrt);
	}

	XFREE(MTYPE_DHCPGW_INTERFACE, dgif);
}

static void dhcpgw_route_free(struct dhcpgw_route *dgrt)
{
	XFREE(MTYPE_TMP, dgrt->command_prefix);
	XFREE(MTYPE_TMP, dgrt->command_suffix);
	XFREE(MTYPE_DHCPGW_ROUTE, dgrt);
}

static struct dhcpgw_interface* dhcpgw_routes_find_interface(const char* ifname)
{
	struct dhcpgw_interface search;
	strlcpy(search.ifname, ifname, sizeof(search.ifname));

	zlog_notice("%s: r4 Searching for interface '%s', all interfaces:", __func__, ifname);
	struct dhcpgw_interface *dgif;
	frr_each (dhcpgw_interface_list, &interfaces_list_head, dgif) {
		zlog_notice("* '%s'", dgif->ifname);
	}
	zlog_notice("With result: %p", dhcpgw_interface_list_find(&interfaces_list_head, &search));

	return dhcpgw_interface_list_find(&interfaces_list_head, &search);
}

static struct dhcpgw_interface* dhcpgw_routes_find_or_create_interface(const char* ifname)
{
	struct dhcpgw_interface *dgif = dhcpgw_routes_find_interface(ifname);
	union g_addr ip_addr;

	if (dgif)
		return dgif;

	dgif = XCALLOC(MTYPE_DHCPGW_INTERFACE, sizeof(struct dhcpgw_interface));
	strlcpy(dgif->ifname, ifname, sizeof(dgif->ifname));
	dhcpgw_route_list_init(&dgif->routes_head);
	/* Setting dgif->ifname before list_add is critical: it is the key*/
	dhcpgw_interface_list_add(&interfaces_list_head, dgif);
	dgif->last_ip_str[0] = '\0';

	if (dhcpgw_state_read(dgif->ifname, &dgif->last_up, &dgif->last_af, &ip_addr))
		dgif->last_up = false;
	else {
		if (!inet_ntop(dgif->last_af, &ip_addr, dgif->last_ip_str, sizeof(dgif->last_ip_str))) {
			zlog_warn("%s: Couldn't convert provided ip to string: %s", __func__, strerror(errno));
			dgif->last_up = false;
		}
	}
	return dgif;
}

static struct dhcpgw_route* dhcpgw_routes_find_route(struct dhcpgw_interface *dgif,
		const char* command_prefix, const char* command_suffix)
{
	struct dhcpgw_route *dgrt;
	zlog_notice("%s: Search in interface %s for route with prefix='%s', suffix='%s'", //DEBUG
			__func__, dgif->ifname, command_prefix, command_suffix);

	frr_each (dhcpgw_route_list, &dgif->routes_head, dgrt) {
		zlog_notice("...trying route af=%d, prefix='%s', suffix='%s'", dgrt->af, dgrt->command_prefix, dgrt->command_suffix); //DEBUG

		if (strcmp(dgrt->command_prefix, command_prefix)) {
			zlog_notice("...Wrong prefix, continue"); //DEBUG
			continue;
		}
		if (strcmp(dgrt->command_suffix, command_suffix)) {
			zlog_notice("...Wrong suffix, continue"); //DEBUG
			continue;
		}
		zlog_notice("...YES!"); //DEBUG
		return dgrt;
	}

	zlog_notice("...NO, return NULL"); //DEBUG
	return NULL;
}

static void dhcpgw_route_delete(struct dhcpgw_interface* dgif, struct dhcpgw_route* dgrt)
{
	staticd_route_change_enqueue(true, dgif, dgrt);
	dhcpgw_route_list_del(&dgif->routes_head, dgrt);
	dhcpgw_route_free(dgrt);
}

static void dhcpgw_route_add(struct dhcpgw_interface* dgif, int af,
		const char* command_prefix, const char* command_suffix)
{
	struct dhcpgw_route* dgrt = XCALLOC(MTYPE_DHCPGW_ROUTE, sizeof(struct dhcpgw_route));
	dgrt->command_prefix = XSTRDUP(MTYPE_TMP, command_prefix);
	dgrt->command_suffix = XSTRDUP(MTYPE_TMP, command_suffix);
	dhcpgw_route_list_add_tail(&dgif->routes_head, dgrt);
	staticd_route_change_enqueue(false, dgif, dgrt);
}

static void staticd_route_change_enqueue(bool no, struct dhcpgw_interface* dgif, struct dhcpgw_route *dgrt)
{
	zlog_notice("staticd_route Calling no=%d, dgrt->prefix=%s, dgrt->suffix=%s, dgif->ifname=%s, dgif->last_ip_str=%s",
			no, dgrt->command_prefix, dgrt->command_suffix, dgif->ifname, dgif->last_ip_str); // DEBUG
	const char *gateway_ip = dgif->last_ip_str;
	const char *prefix = dgrt->command_prefix;
	const char *suffix = dgrt->command_suffix;
	/* TODO How to send command to staticd properly? */
	const char *shell_prefix = "(sleep 0.$((1 + $RANDOM % 9)) && vtysh -c 'configure' -c '";
	const char *shell_suffix = "') &";
	const char *no_str = "no ";

	if (!dgif->last_up) {
		zlog_notice("%s: dgif is down, nothing to do", __func__); // DEBUG
		return;
	}

	int len = strlen(prefix) + strlen(gateway_ip) + strlen(suffix) + 3 + strlen(shell_prefix) + strlen(shell_suffix) + 1;
	if (no) {
		len += strlen(no_str);
	}

	char *shell_cmd = XMALLOC(MTYPE_TMP, len);

	strlcpy(shell_cmd, shell_prefix, len);
	if (no) {
		strlcat(shell_cmd, no_str, len);
	}
	strlcat(shell_cmd, prefix, len);
	strlcat(shell_cmd, " ", len);
	strlcat(shell_cmd, gateway_ip, len);
	strlcat(shell_cmd, " ", len);
	strlcat(shell_cmd, suffix, len);
	strlcat(shell_cmd, shell_suffix, len);

	zlog_notice("HEDROK! (for) staticd_route run shell cmd: {[%s]}", shell_cmd); // DEBUG
	int ret = system(shell_cmd);
	zlog_notice("return value: %d", ret); // DEBUG

	XFREE(MTYPE_TMP, shell_cmd);
}

/* extern */

extern void dhcpgw_routes_init(struct event_loop *)
{
	dhcpgw_interface_list_init(&interfaces_list_head);
}

extern void dhcpgw_routes_close(void)
{
	struct dhcpgw_interface *dgif;

	while ((dgif = dhcpgw_interface_list_pop(&interfaces_list_head)))
		dhcpgw_interface_free(dgif);
}

extern void dhcpgw_routes_process(bool no, const char* ifname, int af, const char*
		command_prefix, const char* command_suffix)
{
	zlog_notice("%s: no=%d, ifname=%s, af=%d, command_prefix=%s, command_suffix=%s", //DEBUG
			__func__, no, ifname, af, command_prefix, command_suffix); //DEBUG
	/*
	 * 1. Find or create appropriate dhcpgw_interface
	 * 2. Search for same route in interface list
	 * 2.1 If found and no == true, delete it, remove route from staticd if needed, exit
	 * 2.2 If found and no == false, do nothing, exit
	 * 2.3 If not found and no == true, do nothng, exit
	 * else (found == false && no == false)
	 * 3. Add route to list
	 * 4. Add route to staticd
	 */
	struct dhcpgw_interface *dgif;
	if (no) {
		dgif = dhcpgw_routes_find_interface(ifname);
		if (!dgif) {
			zlog_notice("%s: No routes for %s, nothing to delete", __func__, ifname); // DEBUG
			return;
		}
	} else
		dgif = dhcpgw_routes_find_or_create_interface(ifname);

	struct dhcpgw_route *dgrt = dhcpgw_routes_find_route(dgif, command_prefix, command_suffix);
	if (dgrt) {
		zlog_notice("%s: ...found dgrt!", __func__); // DEBUG
		if (no) {
			zlog_notice("%s: ...dhcpgw_route_delete", __func__); // DEBUG
			dhcpgw_route_delete(dgif, dgrt);
			/* If there is no route left for interface delete it from list */
			if (dhcpgw_route_list_first(&dgif->routes_head) == NULL) {
				dhcpgw_interface_list_del(&interfaces_list_head, dgif);
				dhcpgw_interface_free(dgif);
			}
		} else {
			zlog_notice("%s: ...ignore", __func__); // DEBUG
		}
		return;
	}
	if (no) {
		zlog_notice("%s: ...not found + no=true, return", __func__); // DEBUG
		return;
	}
	zlog_notice("%s: ...dhcpgw_route_add", __func__); // DEBUG
	dhcpgw_route_add(dgif, af, command_prefix, command_suffix);
}


extern void dhcpgw_routes_update_interface(const char* ifname)
{
	zlog_notice("%s: ifname=%s", __func__, ifname);

	struct dhcpgw_interface* dgif = dhcpgw_routes_find_interface(ifname);

	if (!dgif) {
		zlog_notice("...nothing to do, no routes for this ifname");
		return;
	}

	bool new_up;
	int new_af;
	char new_ip_str[INET6_ADDRSTRLEN];
	union g_addr ip_addr;

	if (dhcpgw_state_read(ifname, &new_up, &new_af, &ip_addr)) {
		new_up = false;
	} else {
		if (new_up) {
			if (!inet_ntop(new_af, &ip_addr, new_ip_str, sizeof(new_ip_str))) {
				zlog_warn("%s: Couldn't convert provided ip to string: %s", __func__, strerror(errno));
				new_up = false;
			}
		}
	}

	if (dgif->last_up == new_up && !strcmp(dgif->last_ip_str, new_ip_str)) {
		zlog_notice("...nothing to do, state and IP didn't change: dgif->last_up=%d, new_up=%d", dgif->last_up, new_up);
		if (new_up) {
			zlog_notice("......dgif->last_ip_str=%s, new_ip_str=%s", dgif->last_ip_str, new_ip_str);
		}
		return;
	}

	struct dhcpgw_route *dgrt;

	/* If previous state was up, deinstall all previous routes */
	if (dgif->last_up) {
		frr_each (dhcpgw_route_list, &dgif->routes_head, dgrt) {
			zlog_notice("...deleting route af=%d, prefix='%s', suffix='%s'", dgrt->af, dgrt->command_prefix, dgrt->command_suffix);
			staticd_route_change_enqueue(true, dgif, dgrt);
		}
	}

	/* Updating interface data */
	dgif->last_up = new_up;
	dgif->last_af = new_af;
	strlcpy(dgif->last_ip_str, new_ip_str, sizeof(dgif->last_ip_str));

	/* If new state is up, install all new routes */
	if (dgif->last_up) {
		frr_each (dhcpgw_route_list, &dgif->routes_head, dgrt) {
			zlog_notice("...installing route af=%d, prefix='%s', suffix='%s'", dgrt->af, dgrt->command_prefix, dgrt->command_suffix);
			staticd_route_change_enqueue(false, dgif, dgrt);
		}
	}
}

extern void do_show_dhcpgw_routes(struct vty* vty)
{
	/* TODO use_json ignored */
	struct dhcpgw_interface* dgif;
	struct dhcpgw_route* dgrt;

	frr_each (dhcpgw_interface_list, &interfaces_list_head, dgif) {
		vty_out(vty, "interface %s: state=%s", dgif->ifname, dgif->last_up ? "UP" : "DOWN");
		if (dgif->last_up) {
			vty_out(vty, ", IP=%s", dgif->last_ip_str);
		}
		vty_out(vty, "\n");

		frr_each (dhcpgw_route_list, &dgif->routes_head, dgrt) {
			vty_out(vty, "\t%s " DHCP_GATEWAY_CMD_STR " %s\n", dgrt->command_prefix, dgrt->command_suffix);
		}
	}
}

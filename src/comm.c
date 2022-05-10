/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/tree.h>
#include <sys/queue.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <assert.h>
#include <pthread.h>

#include <ev.h>

#include <mand/logx.h>
#include <mand/binary.h>

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include <libdmconfig/codes.h>
#include <libdmconfig/dmmsg.h>
#include <libdmconfig/dmcontext.h>
#include <libdmconfig/dmconfig.h>
#include <libdmconfig/dm_dmconfig_rpc_stub.h>
#include <libdmconfig/dm_dmclient_rpc_impl.h>

#include "cfgd.h"
#include "comm.h"

#define IF_IP     (1 << 0)
#define IF_NEIGH  (1 << 1)

#define CB_ERR(...) \
	do {					\
		logx(LOG_ERR, __VA_ARGS__);	\
		return;				\
	} while (0)
#define CB_ERR_RET(ret, ...)			\
	do {					\
		logx(LOG_ERR, __VA_ARGS__);	\
		return ret;			\
	} while (0)

#define chomp(s) ({ \
	char *c = (s) + strlen((s)) - 1; \
	while ((c > (s)) && (*c == '\n' || *c == '\r' || *c == ' ')) \
	        *c-- = '\0'; \
	s; \
})

#define MEGABYTE (1024U * 1024U)
#define SYSTEM_MONITORING_REPORT_INTERVAL_S (10 * 60)

/**
 * Port that metropolis-fwd listens on.
 * @bug This might actually potentially differ between Metropolis images.
 */
#define METROPOLIS_FWD_PORT 40000

typedef void (*DECODE_CB)(DMCONTEXT *socket, const char *name, uint32_t code, uint32_t vendor_id,
	                  void *data, size_t size, void *cb_data);

static void new_var_list(void *ctx, struct var_list *list, size_t size)
{
	memset(list, 0, sizeof(struct var_list));
	list->ctx = ctx;
}

static void *add_var_list(struct var_list *list, size_t size)
{
	void *p;

	if ((list->count % 16) == 0) {
		if (!(list->data = talloc_realloc_size(list->ctx, list->data, size * (list->count + 16))))
			return NULL;
	}
	list->count++;

	p = ((void *)list->data) + (list->count - 1) * size;
	memset(p, 0, size);

	return p;
}

static void new_string_list(void *ctx, struct string_list *list)
{
	new_var_list(ctx, (struct var_list *)list, sizeof(char *));
}

static void add_string_list(struct string_list *list, const void *data, size_t size)
{
	void **d;

	if (!(d = add_var_list((struct var_list *)list, sizeof(char *))))
		return;

	*d = talloc_strndup(list->ctx, data, size);
}

static uint32_t
decode_node_list(DMCONTEXT *socket, const char *prefix, DM2_AVPGRP *grp, DECODE_CB cb, void *cb_data)
{
	uint32_t r;
	DM2_AVPGRP container;
	uint32_t code;
	uint32_t vendor_id;
	void *data;
	size_t size;

	char *name, *path;
	uint16_t id;
	uint32_t type;

	if ((r = dm_expect_avp(grp, &code, &vendor_id, &data, &size)) != RC_OK)
		return r;

	if (vendor_id != VP_TRAVELPING)
		return RC_ERR_MISC;

	dm_init_avpgrp(grp->ctx, data, size, &container);

	switch (code) {
	case AVP_TABLE:
		if ((r = dm_expect_string_type(&container, AVP_NAME, VP_TRAVELPING, &name)) != RC_OK)
			return r;

		if (!(path = talloc_asprintf(container.ctx, "%s.%s", prefix, name)))
			return RC_ERR_ALLOC;

		while (decode_node_list(socket, path, &container, cb, cb_data) == RC_OK) {
		}

		break;

	case AVP_INSTANCE:
		if ((r = dm_expect_uint16_type(&container, AVP_NAME, VP_TRAVELPING, &id)) != RC_OK)
			return r;

		if (!(path = talloc_asprintf(container.ctx, "%s.%d", prefix, id)))
			return RC_ERR_ALLOC;

		while (decode_node_list(socket, path, &container, cb, cb_data) == RC_OK) {
		}

		break;

	case AVP_OBJECT:
		if ((r = dm_expect_string_type(&container, AVP_NAME, VP_TRAVELPING, &name)) != RC_OK)
			return r;

		if (!(path = talloc_asprintf(container.ctx, "%s.%s", prefix, name)))
			return RC_ERR_ALLOC;

		while (decode_node_list(socket, path, &container, cb, cb_data) == RC_OK) {
		}

		break;

	case AVP_ELEMENT:
		if ((r = dm_expect_string_type(&container, AVP_NAME, VP_TRAVELPING, &name)) != RC_OK
		    || (r = dm_expect_uint32_type(&container, AVP_TYPE, VP_TRAVELPING, &type)) != RC_OK)
			return r;

		if (!(path = talloc_asprintf(container.ctx, "%s.%s", prefix, name)))
			return RC_ERR_ALLOC;

		if ((r = dm_expect_avp(&container, &code, &vendor_id, &data, &size)) != RC_OK)
			return r;

		cb(socket, path, code, vendor_id, data, size, cb_data);
		break;

	case AVP_ARRAY:
		if ((r = dm_expect_string_type(&container, AVP_NAME, VP_TRAVELPING, &name)) != RC_OK
		    || (r = dm_expect_uint32_type(&container, AVP_TYPE, VP_TRAVELPING, &type)) != RC_OK)
			return r;

		if (!(path = talloc_asprintf(container.ctx, "%s.%s", prefix, name)))
			return RC_ERR_ALLOC;

		while (dm_expect_group_end(&container) != RC_OK) {
			if ((r = dm_expect_avp(&container, &code, &vendor_id, &data, &size)) != RC_OK)
				return r;
			cb(socket, path, code, vendor_id, data, size, cb_data);
		}
		break;

	default:
		return RC_ERR_MISC;
	}

	return RC_OK;
}

/** apply the values from system.ntp.server list to the systemd configuration
 *
 * NOTE: this version cut some corners, more carefull check are needed when/if
 *       the datamodel also supports TCP
 */
static void
ntp_cb(DMCONTEXT *socket, const char *name, uint32_t code, uint32_t vendor_id,
       void *data, size_t size, void *cb_data)
{
	struct ntp_servers *srvs = (struct ntp_servers *)cb_data;
	const char *s;

	if (!(s = strrchr(name, '.')))
		return;

	if (strncmp(s + 1, "enabled", 7) == 0) {
		srvs->enabled = dm_get_uint8_avp(data);
	} else if (strncmp(s + 1, "address", 7) == 0) {
		if ((srvs->count % 16) == 0) {
			srvs->server = talloc_realloc(NULL, srvs->server, char *, srvs->count + 16);
			if (!srvs->server)
				return;
		}
		srvs->server[srvs->count] = talloc_strndup(srvs->server, data, size);
		srvs->count++;
	}
}

static void
ntpListReceived(DMCONTEXT *socket, DMCONFIG_EVENT event, DM2_AVPGRP *grp, void *userdata __attribute__((unused)))
{
	uint32_t rc, answer_rc;
	struct ntp_servers srvs;

	if (event != DMCONFIG_ANSWER_READY)
	        CB_ERR("Couldn't list object, ev=%d.\n", event);

	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &answer_rc)) != RC_OK
	    || answer_rc != RC_OK)
	        CB_ERR("Couldn't list object, rc=%d,%d.\n", rc, answer_rc);

	srvs.enabled = 0;
	srvs.count = 0;
	srvs.server = talloc_array(grp->ctx, char *, 16);
	if (!srvs.server)
		return;

	while (decode_node_list(socket, "", grp, ntp_cb, &srvs) == RC_OK) {
	}

	set_ntp_server(&srvs);
}

static void
listSystemNtp(DMCONTEXT *dmCtx)
{
	if (rpc_db_list_async(dmCtx, 0, "system.ntp", ntpListReceived, NULL))
	        CB_ERR("Couldn't register LIST request.\n");
}

static void
ptpGetReceived(DMCONTEXT *socket, DMCONFIG_EVENT event, DM2_AVPGRP *grp,
               void *userdata __attribute__((unused)))
{
	uint32_t rc, answer_rc;
	char *ptp_state;

	if (event != DMCONFIG_ANSWER_READY)
	        CB_ERR("Couldn't get \"system.ptp.state\", ev=%d.\n", event);

	/*
	 * This depends on the metropolis-ptp Yang module,
	 * which is not in every Metropolis build.
	 * Therefore we handle errors gracefully.
	 */
	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &answer_rc)) != RC_OK
	    || answer_rc != RC_OK) {
	        logx(LOG_INFO, "Couldn't get \"system.ptp.state\", rc=%d,%d.\n", rc, answer_rc);
		return;
	}

	if ((rc = dm_expect_string_type(grp, AVP_ENUM, VP_TRAVELPING, &ptp_state)) != RC_OK ||
	    (rc = dm_expect_group_end(grp)) != RC_OK)
		CB_ERR("Couldn't decode GET request, rc=%d", rc);

	set_ptp_state(ptp_state);
}

static void
listSystemPtp(DMCONTEXT *dmCtx)
{
	static const char *paths[] = {
		"system.ptp.state"
	};

	uint32_t rc;

	rc = rpc_db_get_async(dmCtx, sizeof(paths)/sizeof(paths[0]), paths, ptpGetReceived, NULL);
	if (rc != RC_OK)
		CB_ERR("Couldn't get \"system.ptp.state\", rc=%d", rc);
}

/** apply the values from system.dns.server list to the systemd configuration
 *
 * NOTE: this version cut some corners, more carefull check are needed when/if
 *       the datamodel also supports TCP
 */
struct dns_params {
	struct string_list search;
	struct string_list srvs;
};

static void
dns_cb(DMCONTEXT *socket, const char *name, uint32_t code, uint32_t vendor_id,
       void *data, size_t size, void *cb_data)
{
	struct dns_params *info = (struct dns_params *)cb_data;
	const char *s;

	if (!(s = strrchr(name, '.')))
		return;

	if (strncmp(s + 1, "search", 6) == 0) {
		add_string_list(&info->search, data, size);
	} else if (strncmp(s + 1, "address", 7) == 0) {
		add_string_list(&info->srvs, data, size);
	}
}

static void
dnsListReceived(DMCONTEXT *socket, DMCONFIG_EVENT event, DM2_AVPGRP *grp,
	        void *userdata __attribute__((unused)))
{
	uint32_t rc, answer_rc;
	struct dns_params info;

	if (event != DMCONFIG_ANSWER_READY)
	        CB_ERR("Couldn't list object, ev=%d.\n", event);

	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &answer_rc)) != RC_OK
	    || answer_rc != RC_OK)
	        CB_ERR("Couldn't list object, rc=%d,%d.\n", rc, answer_rc);

	new_string_list(grp->ctx, &info.search);
	new_string_list(grp->ctx, &info.srvs);

	while (decode_node_list(socket, "", grp, dns_cb, &info) == RC_OK) {
	}

	set_dns(&info.search, &info.srvs);
}

static void
listSystemDns(DMCONTEXT *dmCtx)
{
	if (rpc_db_list_async(dmCtx, 0, "system.dns-resolver", dnsListReceived, NULL))
	        CB_ERR("Couldn't register LIST request.\n");
}

/***************************************/

static void
ssh_key(const char *name, void *data, size_t size, struct auth_ssh_key_list *list)
{
	if (strncmp(name, "name", 4) == 0) {
		struct auth_ssh_key *d;

		if (!(d = add_var_list((struct var_list *)list, sizeof(struct auth_ssh_key))))
			return;

		d->name = talloc_strndup(list->ctx, data, size);
	} else if (strncmp(name, "algorithm", 9) == 0) {
		list->ssh[list->count - 1].algo = talloc_strndup(list->ctx, data, size);
	} else if (strncmp(name, "key-data", 8) == 0) {
		list->ssh[list->count - 1].data = talloc_size(list->ctx, size * 2);
		dm_to64(data, size, list->ssh[list->count - 1].data);
	}
}

static void
auth_cb(DMCONTEXT *socket, const char *name, uint32_t code, uint32_t vendor_id,
	void *data, size_t size, void *cb_data)
{
	struct auth_list *info = (struct auth_list *)cb_data;
	const char *s;

	if (!(s = strchr(name + 1, '.')))
		return;
	if (!(s = strchr(s + 1, '.')))
		return;

	if (strncmp(s + 1, "name", 4) == 0) {
		struct auth_user *d;

		logx(LOG_DEBUG, "user (%d): %*s", info->count, (int)size, (char *)data);
		if (!(d = add_var_list((struct var_list *)info, sizeof(struct auth_user))))
			return;

		new_var_list(info->ctx, (struct var_list *)&d->ssh, sizeof(struct auth_ssh_key_list));

		d->name = talloc_strndup(info->ctx, data, size);
	} else if (strncmp(s + 1, "password", 8) == 0) {
		logx(LOG_DEBUG, "pass: %*s", (int)size, (char *)data);
		info->user[info->count - 1].password = talloc_strndup(info->ctx, data, size);
	} else {
		if (strncmp(s + 1, "ssh-key.", 8) == 0) {
			if (!(s = strchr(s + 10, '.')))
				return;

			ssh_key(s + 1, data, size, &info->user[info->count - 1].ssh);
		}
	}
}

static void
AuthListReceived(DMCONTEXT *socket, DMCONFIG_EVENT event, DM2_AVPGRP *grp,
	         void *userdata __attribute__((unused)))
{
	uint32_t rc, answer_rc;
	struct auth_list auth;

	if (event != DMCONFIG_ANSWER_READY)
	        CB_ERR("Couldn't list object, ev=%d.\n", event);

	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &answer_rc)) != RC_OK
	    || answer_rc != RC_OK)
	        CB_ERR("Couldn't list object, rc=%d,%d.\n", rc, answer_rc);

	new_var_list(grp->ctx, (struct var_list *)&auth, sizeof(struct auth_user));

	while (decode_node_list(socket, "", grp, auth_cb, &auth) == RC_OK) {
	}

	set_authentication(&auth);
}

static void
listAuthentication(DMCONTEXT *dmCtx)
{
	if (rpc_db_list_async(dmCtx, 0, "system.authentication.user", AuthListReceived, NULL))
	        CB_ERR("Couldn't register LIST request.\n");
}

/** apply the values from interfaces.interface to the systemd configuration
 *
 * NOTE: this version cut some corners, more carefull check are needed when/if
 *       the datamodel also supports TCP
 */
struct if_params {
	struct string_list search;
	struct string_list srvs;
};

static void
dhcp_client_cb(DMCONTEXT *socket, const char *name, uint32_t code, uint32_t vendor_id,
               void *data, size_t size, void *cb_data)
{
	struct interface_list *info = (struct interface_list *)cb_data;
	const char *s;

	if (!(s = strchr(name + 1, '.')))
		return;
	if (!(s = strchr(s + 1, '.')))
		return;

	if (strncmp(s + 1, "interface", 9) == 0) {
		char *interface = strndup(data, size);
		unsigned int instance_id;

		int rc = sscanf(interface, "interfaces.interface.%u", &instance_id);
		free(interface);
		if (rc != 1)
			return;

		for (int i = 0; i < info->count; i++) {
			if (info->iface[i].instance_id == instance_id) {
				info->iface[i].dhcp.enabled = true;
				break;
			}
		}
	}
}

static void
dhcpClientListReceived(DMCONTEXT *socket, DMCONFIG_EVENT event, DM2_AVPGRP *grp, void *userdata)
{
	struct interface_list *info = userdata;
	uint32_t rc, answer_rc;

	if (event != DMCONFIG_ANSWER_READY) {
		talloc_free(info);
		CB_ERR("Couldn't list object, ev=%d.\n", event);
	}

	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &answer_rc)) != RC_OK ||
	    answer_rc != RC_OK) {
		talloc_free(info);
		CB_ERR("Couldn't list object, rc=%d,%d.\n", rc, answer_rc);
	}

	while (decode_node_list(socket, "", grp, dhcp_client_cb, info) == RC_OK);

	if (info->flags & IF_NEIGH)
		set_if_neigh(info);
	if (info->flags & IF_IP)
		set_if_addr(info);

	talloc_free(info);
}

static void
if_ip_addr(const char *name, void *data, size_t size, struct ip_list *list)
{
	const char *s;

	if (!(s = strchr(name + 1, '.')))
		return;

	if (strncmp("ip", s + 1, 2) == 0) {
		char b[INET6_ADDRSTRLEN];
		int af;
		struct in6_addr addr;
		struct ipaddr *d;

		if (!(d = add_var_list((struct var_list *)list, sizeof(struct ipaddr))))
			return;

		dm_get_address_avp(&af, &addr, sizeof(addr), data, size);
		inet_ntop(af, &addr, b, sizeof(b));
		d->af = af;
		d->address = talloc_strdup(list->ctx, b);
	} else if (size != 0 && strncmp("prefix-length", s + 1, 13) == 0) {
		struct ipaddr *d = list->ip + list->count - 1;
		d->value = talloc_asprintf(list->ctx, "%u", dm_get_uint32_avp(data));
	}
}

static void
if_ip_neigh(const char *name, void *data, size_t size, struct ip_list *list)
{
	const char *s;

	if (!(s = strchr(name + 1, '.')))
		return;

	if (strncmp("ip", s + 1, 2) == 0) {
		char b[INET6_ADDRSTRLEN];
		int af;
		struct in6_addr addr;
		struct ipaddr *d;

		if (!(d = add_var_list((struct var_list *)list, sizeof(struct ipaddr))))
			return;

		dm_get_address_avp(&af, &addr, sizeof(addr), data, size);
		inet_ntop(af, &addr, b, sizeof(b));
		d->address = talloc_strdup(list->ctx, b);
	} else if (strncmp("link-layer-address", s + 1, 20) == 0) {
		struct ipaddr *d = list->ip + list->count - 1;

		d->value = talloc_strndup(list->ctx, data, size);
	}
}

static void
if_ip_gateway(void *data, size_t size, struct ip_list *list)
{
	char b[INET6_ADDRSTRLEN];
	struct in6_addr addr;
	struct ipaddr *d;

	if (!(d = add_var_list((struct var_list *)list, sizeof(struct ipaddr))))
		return;

	dm_get_address_avp(&d->af, &addr, sizeof(addr), data, size);
	inet_ntop(d->af, &addr, b, sizeof(b));
	d->address = talloc_strdup(list->ctx, b);
}

static void
if_ip(const char *name, void *data, size_t size, struct if_ip *if_ip)
{
	if (strncmp("enabled", name, 7) == 0) {
		if_ip->enabled = dm_get_uint8_avp(data);
	} else if (strncmp("forwarding", name, 9) == 0) {
		if_ip->forwarding = dm_get_uint8_avp(data);
	} else if (strncmp("mtu", name, 3) == 0) {
		if_ip->mtu = dm_get_uint32_avp(data);
	} else if (strncmp("address", name, 7) == 0) {
		if_ip_addr(name + 8, data, size, &if_ip->addr);
	} else if (strncmp("neighbor", name, 8) == 0) {
		if_ip_neigh(name + 9, data, size, &if_ip->neigh);
	} else if (strncmp("gateway-ip", name, 10) == 0) {
		/*
		 * NOTE: gateway-ip is a Metropolis extension.
		 * It is an array of IPv4/v6 addresses.
		 */
		if_ip_gateway(data, size, &if_ip->gateway);
	}
}

static void
if_cb(DMCONTEXT *socket, const char *name, uint32_t code, uint32_t vendor_id,
      void *data, size_t size, void *cb_data)
{
	struct interface_list *info = (struct interface_list *)cb_data;
	const char *s;

	if (!(s = strchr(name + 1, '.')))
		return;
	if (!(s = strchr(s + 1, '.')))
		return;

	if (strncmp(s + 1, "name", 4) == 0) {
		struct interface *d;

		if (!(d = add_var_list((struct var_list *)info, sizeof(struct interface))))
			return;

		new_var_list(info->ctx, (struct var_list *)&d->ipv4.addr, sizeof(struct ip_list));
		new_var_list(info->ctx, (struct var_list *)&d->ipv4.neigh, sizeof(struct ip_list));
		new_var_list(info->ctx, (struct var_list *)&d->ipv4.gateway, sizeof(struct ip_list));
		new_var_list(info->ctx, (struct var_list *)&d->ipv6.addr, sizeof(struct ip_list));
		new_var_list(info->ctx, (struct var_list *)&d->ipv6.neigh, sizeof(struct ip_list));
		new_var_list(info->ctx, (struct var_list *)&d->ipv6.gateway, sizeof(struct ip_list));

		d->name = talloc_strndup(info->ctx, data, size);

		sscanf(name, ".interface.%u", &d->instance_id);
	} else if (strncmp(s + 1, "ipv4", 4) == 0) {
		if_ip(s + 6, data, size, &info->iface[info->count - 1].ipv4);
	} else if (strncmp(s + 1, "ipv6", 4) == 0) {
		if_ip(s + 6, data, size, &info->iface[info->count - 1].ipv6);
	}
}

static void
ifListReceived(DMCONTEXT *socket, DMCONFIG_EVENT event, DM2_AVPGRP *grp, void *userdata)
{
	uint32_t rc, answer_rc;

	if (event != DMCONFIG_ANSWER_READY)
	        CB_ERR("Couldn't list object, ev=%d.\n", event);

	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &answer_rc)) != RC_OK
	    || answer_rc != RC_OK)
	        CB_ERR("Couldn't list object, rc=%d,%d.\n", rc, answer_rc);

	struct interface_list *info = talloc(socket, struct interface_list);
	new_var_list(socket, (struct var_list *)info, sizeof(struct interface));
	info->flags = (unsigned int)(size_t)userdata;

	while (decode_node_list(socket, "", grp, if_cb, info) == RC_OK);

	if (rpc_db_list_async(socket, 0, "dhcp.client.interfaces",
	                      dhcpClientListReceived, info)) {
		talloc_free(info);
		CB_ERR("Couldn't register LIST request.\n");
	}
}

static void
listInterfaces(DMCONTEXT *dmCtx, unsigned int flags)
{
	if (rpc_db_list_async(dmCtx, 0, "interfaces.interface", ifListReceived,
	                      (void *)(size_t)flags))
	        CB_ERR("Couldn't register LIST request.\n");
}

static void
sparkplugReceived(DMCONTEXT *dmCtx, DMCONFIG_EVENT event, DM2_AVPGRP *grp,
                  void *userdata __attribute__((unused)))
{
	uint32_t rc, answer_rc;

	if (event != DMCONFIG_ANSWER_READY)
	        CB_ERR("Couldn't get remaining Sparkplug parameters, ev=%d.\n", event);

	/*
	 * NOTE: We don't get here unless the previous GET was successful,
	 * so we know we've got the necessary metropolis-sparkplug Yang module.
	 */
	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &answer_rc)) != RC_OK
	    || answer_rc != RC_OK)
		CB_ERR("Couldn't get remaining Sparkplug parameters, rc=%d,%d.\n",
		       rc, answer_rc);

	char *host, *username, *password;
	/*
	 * FIXME: sparkplug.server.X.port is currently AVP_UINT32.
	 * This could change in the future.
	 */
	uint32_t port;
	uint8_t tls;

	if ((rc = dm_expect_string_type(grp, AVP_STRING, VP_TRAVELPING, &host)) != RC_OK ||
	    (rc = dm_expect_uint32_type(grp, AVP_UINT32, VP_TRAVELPING, &port)) != RC_OK ||
	    (rc = dm_expect_uint8_type(grp, AVP_BOOL, VP_TRAVELPING, &tls)) != RC_OK ||
	    (rc = dm_expect_string_type(grp, AVP_STRING, VP_TRAVELPING, &username)) != RC_OK ||
	    (rc = dm_expect_string_type(grp, AVP_STRING, VP_TRAVELPING, &password)) != RC_OK ||
	    (rc = dm_expect_group_end(grp)) != RC_OK)
		CB_ERR("Couldn't decode GET request, rc=%d", rc);

	set_mosquitto(host, port, tls, username, password);
}

static void
sparkplugCurrentServerReceived(DMCONTEXT *dmCtx, DMCONFIG_EVENT event, DM2_AVPGRP *grp,
                               void *userdata __attribute__((unused)))
{
	uint32_t rc, answer_rc;

	if (event != DMCONFIG_ANSWER_READY)
	        CB_ERR("Couldn't get \"sparkplug.current-server\", ev=%d.\n", event);

	/*
	 * This depends on the metropolis-sparkplug Yang module,
	 * which is not in every Metropolis build.
	 * Therefore we handle errors gracefully.
	 */
	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &answer_rc)) != RC_OK
	    || answer_rc != RC_OK) {
	        logx(LOG_INFO, "Couldn't get \"sparkplug.current-server\", rc=%d,%d.\n",
		     rc, answer_rc);
		return;
	}

	char *current_server;

	if ((rc = dm_expect_string_type(grp, AVP_PATH, VP_TRAVELPING, &current_server)) != RC_OK ||
	    (rc = dm_expect_group_end(grp)) != RC_OK)
		CB_ERR("Couldn't decode GET request, rc=%d", rc);

	/*
	 * NOTE: This is necessary since after adding a new sparkplug.server
	 * and making it the sparkplug.current-server, we need to get informed about
	 * host and port changes as well.
	 * Alternatively, we might add a dm_action and use the broadcast mechanism.
	 */
	rc = rpc_recursive_param_notify_async(dmCtx, NOTIFY_ACTIVE, current_server, NULL, NULL);
	if (rc != RC_OK)
		CB_ERR("Couldn't subscribe for current Sparkplug server, rc=%d", rc);

	char path_host[256], path_port[256], path_tls[256];
	strcat(strcpy(path_host, current_server), ".host");
	strcat(strcpy(path_port, current_server), ".port");
	strcat(strcpy(path_tls, current_server), ".tls");

	const char *paths[] = {
		path_host, /* sparkplug.server.X.host */
		path_port, /* sparkplug.server.X.port */
		path_tls, /* sparkplug.server.X.tls */
		"sparkplug.username",
		"sparkplug.password"
	};

	rc = rpc_db_get_async(dmCtx, sizeof(paths)/sizeof(paths[0]), paths,
	                      sparkplugReceived, NULL);
	if (rc != RC_OK)
		CB_ERR("Couldn't get remaining Sparkplug parameters, rc=%d", rc);
}

static void
listSparkplug(DMCONTEXT *dmCtx)
{
	static const char *paths[] = {
		"sparkplug.current-server"
	};

	uint32_t rc;

	rc = rpc_db_get_async(dmCtx, sizeof(paths)/sizeof(paths[0]), paths,
	                      sparkplugCurrentServerReceived, NULL);
	if (rc != RC_OK)
		CB_ERR("Couldn't get \"%s\", rc=%d", paths[0], rc);
}

static void
wwan4Greceived(DMCONTEXT *dmCtx, DMCONFIG_EVENT event, DM2_AVPGRP *grp,
               void *userdata __attribute__((unused)))
{
	uint32_t rc, answer_rc;

	if (event != DMCONFIG_ANSWER_READY)
	        CB_ERR("Couldn't get GSM/LTE parameters, ev=%d.\n", event);

	/*
	 * NOTE: We don't get here unless the previous GET was successful,
	 * so we know we've got the necessary metropolis-wwan-4g Yang module.
	 */
	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &answer_rc)) != RC_OK
	    || answer_rc != RC_OK)
		CB_ERR("Couldn't get GSM/LTE parameters, rc=%d,%d.\n",
		       rc, answer_rc);

	uint8_t enabled;
	char *apn, *pin, *mode, *lte_mode;
	DM2_AVPGRP lte_bands_grp;

	if ((rc = dm_expect_uint8_type(grp, AVP_BOOL, VP_TRAVELPING, &enabled)) != RC_OK ||
	    (rc = dm_expect_string_type(grp, AVP_STRING, VP_TRAVELPING, &apn)) != RC_OK ||
	    (rc = dm_expect_string_type(grp, AVP_STRING, VP_TRAVELPING, &pin)) != RC_OK ||
	    (rc = dm_expect_string_type(grp, AVP_ENUM, VP_TRAVELPING, &mode)) != RC_OK ||
	    (rc = dm_expect_string_type(grp, AVP_ENUM, VP_TRAVELPING, &lte_mode)) != RC_OK ||
	    (rc = dm_expect_group(grp, AVP_ARRAY, VP_TRAVELPING, &lte_bands_grp)) != RC_OK ||
	    (rc = dm_expect_group_end(grp)) != RC_OK)
		CB_ERR("Couldn't decode GET request, rc=%d", rc);

	unsigned int i = 0;
	uint8_t lte_bands[32];
	uint32_t band;
	/*
	 * FIXME: The band is currently an AVP_UINT32.
	 * This might change in the future.
	 */
	while (i < sizeof(lte_bands)-1 &&
	       dm_expect_uint32_type(&lte_bands_grp, AVP_UINT32, VP_TRAVELPING, &band) == RC_OK)
		lte_bands[i++] = band;
	lte_bands[i] = 0;
	if (i == sizeof(lte_bands)-1)
	        logx(LOG_ERR, "Too many LTE bands specified");

	if (enabled)
		set_wwan_4g(apn, pin, mode, lte_mode, lte_bands);
	else if (system("systemctl stop metropolis-wwan-4g") < 0)
		logx(LOG_ERR, "Cannot disable GSM/LTE connection");
}

static void
listWWAN4G(DMCONTEXT *dmCtx)
{
	static const char *paths[] = {
		"wwan-4g.enabled",
		"wwan-4g.apn",
		"wwan-4g.pin",
		"wwan-4g.mode",
		"wwan-4g.lte.mode",
		"wwan-4g.lte.band"
	};

	uint32_t rc;

	rc = rpc_db_get_async(dmCtx, sizeof(paths)/sizeof(paths[0]), paths,
	                      wwan4Greceived, NULL);
	if (rc != RC_OK)
		CB_ERR("Couldn't get GSM/LTE parameters, rc=%d", rc);
}

static void
wifiReceived(DMCONTEXT *dmCtx, DMCONFIG_EVENT event, DM2_AVPGRP *grp,
             void *userdata __attribute__((unused)))
{
	uint32_t rc, answer_rc;

	if (event != DMCONFIG_ANSWER_READY)
	        CB_ERR("Couldn't get Wi-Fi parameters, ev=%d.\n", event);

	/*
	 * NOTE: We don't get here unless the previous GET was successful,
	 * so we know we've got the necessary metropolis-wifi Yang module.
	 */
	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &answer_rc)) != RC_OK
	    || answer_rc != RC_OK)
		CB_ERR("Couldn't get Wi-Fi parameters, rc=%d,%d.\n",
		       rc, answer_rc);

	uint8_t enabled;
	char *ssid, *password, *security, *country;

	if ((rc = dm_expect_uint8_type(grp, AVP_BOOL, VP_TRAVELPING, &enabled)) != RC_OK ||
	    (rc = dm_expect_string_type(grp, AVP_STRING, VP_TRAVELPING, &ssid)) != RC_OK ||
	    (rc = dm_expect_string_type(grp, AVP_STRING, VP_TRAVELPING, &password)) != RC_OK ||
	    (rc = dm_expect_string_type(grp, AVP_ENUM, VP_TRAVELPING, &security)) != RC_OK ||
	    (rc = dm_expect_string_type(grp, AVP_STRING, VP_TRAVELPING, &country)) != RC_OK)
		CB_ERR("Couldn't decode GET request, rc=%d", rc);

	if (enabled)
		set_wifi(ssid, password, security, country);
	else if (system("systemctl stop metropolis-wifi") < 0)
		logx(LOG_ERR, "Cannot disable Wi-Fi connection");
}

static void
listWifi(DMCONTEXT *dmCtx)
{
	static const char *paths[] = {
		"wifi.enabled",
		"wifi.ssid",
		"wifi.password",
		"wifi.security",
		"wifi.country"
	};

	uint32_t rc;

	rc = rpc_db_get_async(dmCtx, sizeof(paths)/sizeof(paths[0]), paths,
	                      wifiReceived, NULL);
	if (rc != RC_OK)
		CB_ERR("Couldn't get Wi-Fi parameters, rc=%d", rc);
}

static void
request_cb(DMCONTEXT *socket, DM_PACKET *pkt, DM2_AVPGRP *grp, void *userdata)
{
	DMC_REQUEST req;
	DM2_REQUEST *answer = NULL;

	req.hop2hop = dm_hop2hop_id(pkt);
	req.end2end = dm_end2end_id(pkt);
	req.code = dm_packet_code(pkt);

	logx(LOG_DEBUG, "request_cb: received %s",
	     dm_packet_flags(pkt) & CMD_FLAG_REQUEST ? "request" : "answer");
#ifdef LIBDMCONFIG_DEBUG
	dump_dm_packet(pkt);
#endif

	if ((rpc_dmclient_switch(socket, &req, grp, &answer)) == RC_ERR_ALLOC) {
		dm_context_shutdown(socket, DMCONFIG_OK);
		dm_context_release(socket);
		ev_break(socket->ev, EVBREAK_ALL);
		return;
	}

	if (answer)
		dm_enqueue(socket, answer, REPLY, NULL, NULL);
}

uint32_t rpc_client_active_notify(void *ctx, DM2_AVPGRP *obj)
{
	uint32_t rc;
	bool sparkplug_changed = false;
	bool wwan_4g_changed = false;
	bool wifi_changed = false;

	do {
		DM2_AVPGRP grp;
		uint32_t type;
		char *path;

		if ((rc = dm_expect_object(obj, &grp)) != RC_OK
		    || (rc = dm_expect_uint32_type(&grp, AVP_NOTIFY_TYPE, VP_TRAVELPING, &type)) != RC_OK
		    || (rc = dm_expect_string_type(&grp, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK)
	                CB_ERR_RET(rc, "Couldn't decode active notifications, rc=%d\n", rc);

		switch (type) {
		case NOTIFY_INSTANCE_CREATED:
	                logx(LOG_DEBUG, "Notification: Instance \"%s\" created\n", path);
			break;

		case NOTIFY_INSTANCE_DELETED:
	                logx(LOG_DEBUG, "Notification: Instance \"%s\" deleted\n", path);
			break;

		case NOTIFY_PARAMETER_CHANGED: {
			struct dm2_avp avp;
			char *str;

			if ((rc = dm_expect_uint32_type(&grp, AVP_TYPE, VP_TRAVELPING, &type)) != RC_OK
			    || (rc = dm_expect_value(&grp, &avp)) != RC_OK
			    || (rc = dm_decode_unknown_as_string(type, avp.data, avp.size, &str)) != RC_OK)
				CB_ERR_RET(rc, "Couldn't decode parameter changed notifications, rc=%d\n", rc);

	                logx(LOG_DEBUG, "Notification: Parameter \"%s\" changed to \"%s\"\n", path, str);
			if (!strcmp(path, "system.ptp.state"))
				set_ptp_state(str);
			else
				set_value(path, str);

			break;
	        }
		default:
	                logx(LOG_DEBUG, "Notification: Warning, unknown type: %d\n", type);
			break;
		}

		sparkplug_changed |= strncmp(path, "sparkplug.", 10) == 0;
		wwan_4g_changed |= strncmp(path, "wwan-4g.", 8) == 0;
		wifi_changed |= strncmp(path, "wifi.", 5) == 0;
	} while ((rc = dm_expect_end(obj)) != RC_OK);

	/*
	 * For simplicity, we don't try to parse the notification payload for
	 * sparkplug.* parameters.
	 */
	if (sparkplug_changed)
		listSparkplug(ctx);
	if (wwan_4g_changed)
		listWWAN4G(ctx);
	if (wifi_changed)
		listWifi(ctx);

	return dm_expect_end(obj);
}

/*
 * NOTE: Event broadcasts are dispatched by mand's "action" mechanism.
 * Yang extensions are used to declare which parameter triggers which
 * action and the ordering of actions.
 */
uint32_t rpc_client_event_broadcast(void *ctx, const char *path, uint32_t type)
{
	logx(LOG_DEBUG, "Event: %d on \"%s\"", type, path);

	if (strncmp(path, "system.ntp", 10) == 0)
		listSystemNtp(ctx);
	else if (strncmp(path, "system.dns-resolver", 19) == 0)
		listSystemDns(ctx);
	else if (strncmp(path, "system.authentication", 21) == 0)
		listAuthentication(ctx);
	else if (strncmp(path, "interfaces", 10) == 0)
		listInterfaces(ctx, IF_IP | IF_NEIGH);
	else if (strncmp(path, "dhcp.client", 11) == 0)
		listInterfaces(ctx, IF_IP);

	return RC_OK;
}

static void
hostnameReceived(DMCONTEXT *dmCtx, DMCONFIG_EVENT event, DM2_AVPGRP *grp,
                 void *userdata __attribute__((unused)))
{
	uint32_t rc, answer_rc;

	if (event != DMCONFIG_ANSWER_READY)
	        CB_ERR("Couldn't get hostname parameters, ev=%d.\n", event);

	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &answer_rc)) != RC_OK
	    || answer_rc != RC_OK)
		CB_ERR("Couldn't get hostname parameters, rc=%d,%d.\n",
		       rc, answer_rc);

	char *hostname;

	if ((rc = dm_expect_string_type(grp, AVP_STRING, VP_TRAVELPING, &hostname)) != RC_OK)
		CB_ERR("Couldn't decode GET request, rc=%d", rc);

	if (sethostname(hostname, strlen(hostname)))
		CB_ERR("Couldn't decode GET request: %m");
}

static void
listHostname(DMCONTEXT *dmCtx)
{
	uint32_t rc;

	static const char *paths[] = {
		"system.hostname"
	};

	rc = rpc_db_get_async(dmCtx, sizeof(paths)/sizeof(paths[0]), paths,
	                      hostnameReceived, NULL);
	if (rc != RC_OK)
		CB_ERR("Failed to get configured hostname, rc=%d.", rc);

	rc = rpc_param_notify(dmCtx, NOTIFY_ACTIVE,
	                      sizeof(paths)/sizeof(paths[0]), paths, NULL);
	if (rc != RC_OK)
		CB_ERR("Failed to register notification for \"system.hostname\", rc=%d.", rc);
}

static uint32_t
init_timezone(DMCONTEXT *dmCtx)
{
	uint32_t rc;
	FILE *fpipe;
	char buffer[255];

	struct rpc_db_set_path_value set_value = {
		.path  = "system.clock.timezone-location",
		.value = {
			.code = AVP_ENUM,
			.vendor_id = VP_TRAVELPING,
		},
	};

	fpipe = popen("timedatectl status", "r");
	if (!fpipe)
		return RC_ERR_MISC;

	while (fgets(buffer, sizeof(buffer), fpipe)) {
		char *tz = strstr(buffer, "Time zone: ");
		char *p;

		if (!tz)
			continue;
		tz += 11;

		p = strchr(tz, ' ');
		if (p)
			*p = '\0';

		set_value.value.data = tz;
		set_value.value.size = strlen(tz);

		if ((rc = rpc_db_set(dmCtx, 1, &set_value, NULL)) != RC_OK)
			logx(LOG_WARNING, "Failed to report timezone, rc=%d.", rc);
		break;
	}

	fclose(fpipe);

	if ((rc = rpc_param_notify(dmCtx, NOTIFY_ACTIVE, 1, &set_value.path, NULL)) != RC_OK) {
		ev_break(dmCtx->ev, EVBREAK_ALL);
		CB_ERR_RET(rc, "Couldn't register PARAM NOTIFY request, rc=%d.", rc);
	}

	return RC_OK;
}

/**
 * Timer used to periodically report monitored system parameters.
 */
static ev_timer monitoring_timer;

/**
 * Reports monitored system information.
 * 
 * @param dmCtx The libdmconfig context.
 * @param report_total If total memory size should be reported or not.
 * @return According dmconfig RC.
 * 
 * Currently CPU und RAM usage get reported.
 * In future maybe temperatures will be reported.
 */
static uint32_t
report_system_monitoring_info(DMCONTEXT *dmCtx, bool report_total)
{
	struct sysinfo info;
	uint64_t si_total, si_free;
	uint32_t mem_used, mem_total, mem_free_perc, loads[3], rc;

	if (sysinfo(&info) != 0) {
		logx(LOG_WARNING, "Failed to read sysinfo: %s.",
		     strerror(errno));
		return RC_ERR_MISC;
	}

	si_total = (uint64_t) info.totalram * (uint64_t) info.mem_unit;
	si_free  = (uint64_t) info.freeram * (uint64_t) info.mem_unit;

	mem_total     = (uint32_t) (si_total / MEGABYTE);
	mem_used      = (uint32_t) ((si_total - si_free) / MEGABYTE);
	mem_free_perc = (uint32_t) (si_free * 100 / si_total);

	mem_total     = htonl(mem_total);
	mem_used      = htonl(mem_used);
	mem_free_perc = htonl(mem_free_perc);

	for (int i = 0; i < 3; i++)
		loads[i] = htonl((uint32_t) info.loads[i] * 100 / (1 << SI_LOAD_SHIFT));

	struct rpc_db_set_path_value set_values[] = {
		{
			.path  = "metropolis.memory.memory-used",
			.value = {
				.code = AVP_UINT32,
				.vendor_id = VP_TRAVELPING,
				.data = &mem_used,
				.size = sizeof(mem_used)
			}
		},
		{
			.path  = "metropolis.memory.memory-free-percentage",
			.value = {
				.code = AVP_UINT32,
				.vendor_id = VP_TRAVELPING,
				.data = &mem_free_perc,
				.size = sizeof(mem_free_perc)
			}
		},
		{
			.path  = "metropolis.cpu.load-average-1",
			.value = {
				.code = AVP_UINT32,
				.vendor_id = VP_TRAVELPING,
				.data = &loads[0],
				.size = sizeof(loads[0])
			}
		},
		{
			.path  = "metropolis.cpu.load-average-5",
			.value = {
				.code = AVP_UINT32,
				.vendor_id = VP_TRAVELPING,
				.data = &loads[1],
				.size = sizeof(loads[1])
			}
		},
		{
			.path  = "metropolis.cpu.load-average-15",
			.value = {
				.code = AVP_UINT32,
				.vendor_id = VP_TRAVELPING,
				.data = &loads[2],
				.size = sizeof(loads[2])
			}
		},
		{
			.path  = "metropolis.memory.memory-total",
			.value = {
				.code = AVP_UINT32,
				.vendor_id = VP_TRAVELPING,
				.data = &mem_total,
				.size = sizeof(mem_total)
			}
		}
	};

	int nvalues = sizeof(set_values) / sizeof(set_values[0]);
	if (!report_total)
		nvalues -= 1;

	if ((rc = rpc_db_set_async(dmCtx, nvalues, set_values, NULL, NULL)) != RC_OK)
		logx(LOG_WARNING, "Failed to report system information, rc=%d.", rc);

	return RC_OK;
}

/**
 * Periodically reports system information.
 */
static void
report_system_monitoring_timer_cb(EV_P_ ev_timer *w, int revents)
{
	DMCONTEXT *dmCtx = (DMCONTEXT *) w->data;

	if (report_system_monitoring_info(dmCtx, false) != RC_OK)
		logx(LOG_WARNING, "Failed to report system information.");
}

/**
 * Sets system information initially and starts ev_timer for periodic querying.
 * 
 * @param dmCtx The libdmconfig context.
 * @return According dmconfig RC.
 */
static uint32_t
init_system_monitoring(DMCONTEXT *dmCtx)
{
	if (report_system_monitoring_info(dmCtx, true) != RC_OK) {
		logx(LOG_WARNING, "Failed to report system information.");
		return RC_ERR_MISC;
	}

	ev_timer_init(&monitoring_timer, report_system_monitoring_timer_cb,
		      	  5, SYSTEM_MONITORING_REPORT_INTERVAL_S);
	monitoring_timer.data = dmCtx;
	ev_timer_start(dmCtx->ev, &monitoring_timer);

	return RC_OK;
}

static void *
firmware_download_thread_cb(void *user_data)
{
	FILE *file = user_data;
	char buffer[256];

	while (fgets(buffer, sizeof(buffer), file))
		logx(LOG_INFO, "mand_mqtt_thread_cb(): %s", buffer);
	if (!feof(file))
		logx(LOG_ERR, "Error reading from pipe");

	int rc = pclose(file);
	if (rc != 0)
		logx(LOG_ERR, "Error closing pipe: rc=%d", rc);

	/*
	 * FIXME: Do we have to gracefully shut down mand-metropolisd?
	 * Theoretically, metropolis-fwd should shut down the system via
	 * `reboot` which should terminate mand-metropolisd, so we don't
	 * have to do anything.
	 */
	return NULL;
}

uint32_t
rpc_agent_firmware_download(void *ctx, char *url, uint8_t credentialstype, char *credential,
                            char *install_target, uint32_t timeframe, uint8_t retry_count,
                            uint32_t retry_interval, uint32_t retry_interval_increment,
                            DM2_REQUEST *answer)
{
	logx(LOG_DEBUG, "Firmware Upgrade from %s", url);

	bool gzip = strlen(url) >= 3 && !strcmp(url+strlen(url)-3, ".gz");

	/*
	 * NOTE: This disables the metj-flash signature verification, so
	 * we do not have to store the image anywhere.
	 * They can get quite large and do not always fit into ramfs.
	 * Since Metropolis images have their own internal signature that's
	 * verified during flashing, this should not worsen security.
	 *
	 * It would also be possible to integrate libcurl with libev and turn
	 * metj-flash into a library.
	 * Flashing should then probably be handled by a separate daemon.
	 */
	char *url_quoted = quote_shell_arg(url);
	assert(url_quoted != NULL);
	char cmdline[1024];
	snprintf(cmdline, sizeof(cmdline),
	         "(wget -O - \"%s\" | %s metj-flash -K -ed 127.0.0.1:%u) 2>&1",
	         url_quoted, gzip ? "gunzip -c |" : "", METROPOLIS_FWD_PORT);
	free(url_quoted);
	logx(LOG_DEBUG, "Executing: %s", cmdline);
	errno = 0;
	FILE *file = popen(cmdline, "r");
	if (!file) {
		logx(LOG_ERR, "Cannot create pipe to download and flash \"%s\": %m", url);
		return RC_ERR_MISC;
	}

	/*
	 * This is only for reading and logging progress messages.
	 * Should we have to give feedback, we should use a libev watcher instead
	 * and use dmconfig to upgrade some state parameter.
	 */
	pthread_t thread;
	errno = pthread_create(&thread, NULL, firmware_download_thread_cb, file);
	if (errno) {
		logx(LOG_ERR, "Cannot start firmware upgrade thread: %m");
		pclose(file);
		return RC_ERR_MISC;
	}

	return RC_OK;
}

void init_comm(struct ev_loop *loop)
{
	uint32_t rc;
	DMCONTEXT *dmCtx;

	/*
	 * Initialize main dmconfig session.
	 */
	if (!(dmCtx = dm_context_new())) {
	        logx(LOG_DEBUG, "Couldn't create socket context.");
	        return;
	}

	dm_context_init(dmCtx, loop, AF_INET, NULL, NULL, request_cb);

	if ((rc = dm_connect(dmCtx)) != RC_OK) {
	        logx(LOG_DEBUG, "Couldn't register connect callback or connecting unsuccessful, rc=%d.", rc);
		dm_context_shutdown(dmCtx, DMCONFIG_ERROR_CONNECTING);
		dm_context_release(dmCtx);
	        return;
	}
	logx(LOG_DEBUG, "Socket connected.");

	if ((rc = rpc_startsession(dmCtx, CMD_FLAG_READWRITE, 0, NULL)) != RC_OK)
	        CB_ERR("Couldn't register start session request, rc=%d.", rc);

	logx(LOG_DEBUG, "Start session request registered.");

	if ((rc = rpc_register_role(dmCtx, "-firmware")) != RC_OK)
	        CB_ERR("Couldn't register role, rc=%d.", rc);
	logx(LOG_DEBUG, "Role registered.");

	if ((rc = rpc_subscribe_notify(dmCtx, NULL)) != RC_OK)
	        CB_ERR("Couldn't register SUBSCRIBE NOTIFY request, rc=%d.", rc);
	logx(LOG_DEBUG, "Notification subscription request registered.");

	if (init_timezone(dmCtx) != RC_OK)
		logx(LOG_WARNING, "Initial update of Timezone failed.");

	if (init_system_monitoring(dmCtx) != RC_OK)
		logx(LOG_WARNING, "Initial update of system monitoring failed.");

	/*
	 * This requires the optional metropolis-ptp Yang module.
	 * It is not part of the Metropolis base profile, so we must be prepared to handle
	 * missing nodes.
	 * This helps to avoid a new image-specific compile-time option.
	 *
	 * NOTE: PTP does not have its own action table.
	 */
	rc = rpc_recursive_param_notify(dmCtx, NOTIFY_ACTIVE, "system.ptp", NULL);
	logx(LOG_INFO, "Registered recursive notification for \"system.ptp\", rc=%d.", rc);

#if 0
	/*
	 * Requires the optional metropolis-pulsarlr Yang module.
	 */
	rc = rpc_recursive_param_notify(dmCtx, NOTIFY_ACTIVE, "pulsarlr", NULL);
	logx(LOG_INFO, "Registered recursive notification for \"pulsarlr\", rc=%d.", rc);
#endif

	/*
	 * Requires the optional metropolis-sparkplug Yang module.
	 */
	rc = rpc_recursive_param_notify(dmCtx, NOTIFY_ACTIVE, "sparkplug", NULL);
	logx(LOG_INFO, "Registered recursive notification for \"sparkplug\", rc=%d.", rc);

	/*
	 * Requires the optional metropolis-wwan-4g Yang module.
	 */
	rc = rpc_recursive_param_notify(dmCtx, NOTIFY_ACTIVE, "wwan-4g", NULL);
	logx(LOG_INFO, "Registered recursive notification for \"wwan-4g\", rc=%d.", rc);

	/*
	 * Requires the optional metropolis-wifi Yang module.
	 */
	rc = rpc_recursive_param_notify(dmCtx, NOTIFY_ACTIVE, "wifi", NULL);
	logx(LOG_INFO, "Registered recursive notification for \"wifi\", rc=%d.", rc);

	/*
	 * NOTE: Beginning with the first asynchronous method call, we must no longer
	 * call synchronous versions.
	 */
	listHostname(dmCtx);
	listSystemNtp(dmCtx);
	listSystemPtp(dmCtx);
	listSystemDns(dmCtx);
	listAuthentication(dmCtx);
	listInterfaces(dmCtx, IF_IP | IF_NEIGH);
	listSparkplug(dmCtx);
	listWWAN4G(dmCtx);
	listWifi(dmCtx);
}

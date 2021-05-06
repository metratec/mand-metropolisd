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
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>

#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <netlink/route/neighbour.h>

#include <linux/ethtool.h>
#include <linux/sockios.h>

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

static int sys_scan(const char *file, const char *fmt, ...)
{
	FILE *fin;
	int rc, _errno;
	va_list vlist;

	fin = fopen(file, "r");
	if (!fin) {
		errno = 0;
		return EOF;
	}

	va_start(vlist, fmt);
	errno = 0;
	rc = vfscanf(fin, fmt, vlist);
	_errno = errno;
	va_end(vlist);

	fclose(fin);

	errno = _errno;
	return rc;
}

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

	uint32_t rc;

	if (!(s = strchr(name + 1, '.')))
		return;
	if (!(s = strchr(s + 1, '.')))
		return;

	if (strncmp(s + 1, "name", 4) == 0) {
		struct interface *d;

		char search_path[256];
		struct dm2_avp search = {
			.code = AVP_PATH,
			.vendor_id = VP_TRAVELPING,
			.data = search_path
		};

		if (!(d = add_var_list((struct var_list *)info, sizeof(struct interface))))
			return;

		new_var_list(info->ctx, (struct var_list *)&d->ipv4.addr, sizeof(struct ip_list));
		new_var_list(info->ctx, (struct var_list *)&d->ipv4.neigh, sizeof(struct ip_list));
		new_var_list(info->ctx, (struct var_list *)&d->ipv4.gateway, sizeof(struct ip_list));
		new_var_list(info->ctx, (struct var_list *)&d->ipv6.addr, sizeof(struct ip_list));
		new_var_list(info->ctx, (struct var_list *)&d->ipv6.neigh, sizeof(struct ip_list));
		new_var_list(info->ctx, (struct var_list *)&d->ipv6.gateway, sizeof(struct ip_list));

		d->name = talloc_strndup(info->ctx, data, size);

		/*
		 * Since we support DHCP clients as specified by ietf-dhcp@2016-08-25.yang,
		 * we need to determine whether an dhcp.client.interfaces.X node exists.
		 * FIXME: Unfortunately, these queries are not atomic.
		 * Also, we will have to use the blocking dmconfig API.
		 */
		search.size = snprintf(search_path, sizeof(search_path),
		                       "interfaces%.*s", (int)(s - name), name);
		rc = rpc_db_findinstance(socket, "dhcp.client.interfaces", "interface", &search, NULL);
		d->dhcp.enabled = rc == RC_OK;
	} else if (strncmp(s + 1, "ipv4", 4) == 0) {
		if_ip(s + 6, data, size, &info->iface[info->count - 1].ipv4);
	} else if (strncmp(s + 1, "ipv6", 4) == 0) {
		if_ip(s + 6, data, size, &info->iface[info->count - 1].ipv6);
	}
}

static void
ifListReceived(DMCONTEXT *socket, DMCONFIG_EVENT event, DM2_AVPGRP *grp, void *userdata)
{
	unsigned int flag = (unsigned int)(size_t)userdata;
	uint32_t rc, answer_rc;
	struct interface_list info;

	if (event != DMCONFIG_ANSWER_READY)
	        CB_ERR("Couldn't list object, ev=%d.\n", event);

	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &answer_rc)) != RC_OK
	    || answer_rc != RC_OK)
	        CB_ERR("Couldn't list object, rc=%d,%d.\n", rc, answer_rc);

	new_var_list(grp->ctx, (struct var_list *)&info, sizeof(struct interface));

	while (decode_node_list(socket, "", grp, if_cb, &info) == RC_OK) {
	}

	if (flag | IF_NEIGH)
		set_if_neigh(&info);
	if (flag | IF_IP)
		set_if_addr(&info);
}

static void
listInterfaces(DMCONTEXT *dmCtx, unsigned int flags)
{
	if (rpc_db_list_async(dmCtx, 0, "interfaces.interface", ifListReceived,
	                      (void *)(size_t)flags))
	        CB_ERR("Couldn't register LIST request.\n");
}

static void
autoIdGetReceived(DMCONTEXT *socket, DMCONFIG_EVENT event, DM2_AVPGRP *grp,
                  void *userdata __attribute__((unused)))
{
	uint32_t rc, answer_rc;
	uint8_t autoid_enabled;

	if (event != DMCONFIG_ANSWER_READY)
	        CB_ERR("Couldn't get \"pulsarlr.autoid-enabled\", ev=%d.\n", event);

	/*
	 * This depends on the metropolis-pulsarlr Yang module,
	 * which is not in every Metropolis build.
	 * Therefore we handle errors gracefully.
	 */
	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &answer_rc)) != RC_OK
	    || answer_rc != RC_OK) {
	        logx(LOG_INFO, "Couldn't get \"pulsarlr.autoid-enabled\", rc=%d,%d.\n", rc, answer_rc);
		return;
	}

	if ((rc = dm_expect_uint8_type(grp, AVP_BOOL, VP_TRAVELPING, &autoid_enabled)) != RC_OK ||
	    (rc = dm_expect_group_end(grp)) != RC_OK)
		CB_ERR("Couldn't decode GET request, rc=%d", rc);

	set_autoid_enabled(autoid_enabled);
}

static void
listAutoId(DMCONTEXT *dmCtx)
{
	static const char *paths[] = {
		"pulsarlr.autoid-enabled"
	};

	uint32_t rc;

	rc = rpc_db_get_async(dmCtx, sizeof(paths)/sizeof(paths[0]), paths, autoIdGetReceived, NULL);
	if (rc != RC_OK)
		CB_ERR("Couldn't get \"%s\", rc=%d", paths[0], rc);
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

	if ((rc = dm_expect_string_type(grp, AVP_STRING, VP_TRAVELPING, &host)) != RC_OK ||
	    (rc = dm_expect_uint32_type(grp, AVP_UINT32, VP_TRAVELPING, &port)) != RC_OK ||
	    (rc = dm_expect_string_type(grp, AVP_STRING, VP_TRAVELPING, &username)) != RC_OK ||
	    (rc = dm_expect_string_type(grp, AVP_STRING, VP_TRAVELPING, &password)) != RC_OK ||
	    (rc = dm_expect_group_end(grp)) != RC_OK)
		CB_ERR("Couldn't decode GET request, rc=%d", rc);

	set_mosquitto(host, port, username, password);
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

	char path_host[256], path_port[256];
	strcat(strcpy(path_host, current_server), ".host");
	strcat(strcpy(path_port, current_server), ".port");

	const char *paths[] = {
		path_host, /* sparkplug.server.X.host */
		path_port, /* sparkplug.server.X.port */
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
wwanReceived(DMCONTEXT *dmCtx, DMCONFIG_EVENT event, DM2_AVPGRP *grp,
             void *userdata __attribute__((unused)))
{
	uint32_t rc, answer_rc;

	if (event != DMCONFIG_ANSWER_READY)
	        CB_ERR("Couldn't get WWAN parameters, ev=%d.\n", event);

	/*
	 * NOTE: We don't get here unless the previous GET was successful,
	 * so we know we've got the necessary metropolis-sparkplug Yang module.
	 */
	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &answer_rc)) != RC_OK
	    || answer_rc != RC_OK)
		CB_ERR("Couldn't get WWAN parameters, rc=%d,%d.\n",
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
	        logx(LOG_ERR, "Too many WWAN bands specified");

	if (enabled)
		set_wwan(apn, pin, mode, lte_mode, lte_bands);
	else if (system("systemctl stop metropolis-wwan") < 0)
		logx(LOG_ERR, "Cannot disable WWAN connection");
}

static void
listWWAN(DMCONTEXT *dmCtx)
{
	static const char *paths[] = {
		"wwan.enabled",
		"wwan.apn",
		"wwan.pin",
		"wwan.mode",
		"wwan.lte.mode",
		"wwan.lte.band"
	};

	uint32_t rc;

	rc = rpc_db_get_async(dmCtx, sizeof(paths)/sizeof(paths[0]), paths,
	                      wwanReceived, NULL);
	if (rc != RC_OK)
		CB_ERR("Couldn't get WWAN parameters, rc=%d", rc);
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
	bool wwan_changed = false;

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
			else if (!strcmp(path, "pulsarlr.autoid-enabled"))
				set_autoid_enabled(strcmp(str, "true") == 0);
			else
				set_value(path, str);

			break;
	        }
		default:
	                logx(LOG_DEBUG, "Notification: Warning, unknown type: %d\n", type);
			break;
		}

		sparkplug_changed |= strncmp(path, "sparkplug.", 10) == 0;
		wwan_changed |= strncmp(path, "wwan.", 5) == 0;
	} while ((rc = dm_expect_end(obj)) != RC_OK);

	/*
	 * For simplicity, we don't try to parse the notification payload for
	 * sparkplug.* parameters.
	 */
	if (sparkplug_changed)
		listSparkplug(ctx);
	if (wwan_changed)
		listWWAN(ctx);

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

static uint32_t if_ioctl(int d, int request, void *data)
{
	int result;

	if (ioctl(d, request, data) == -1) {
		do {
			result = close(d);
		} while (result == -1 && errno == EINTR);
		return RC_ERR_MISC;
	}
	return RC_OK;
}

static void
add_neigh_to_answer(struct nl_object *obj, void *data)
{
	char buf[32];
	DM2_REQUEST *answer = data;
	struct rtnl_neigh *neigh = (struct rtnl_neigh *)obj;

	int family = rtnl_neigh_get_family(neigh);
	uint8_t *dst = nl_addr_get_binary_addr(rtnl_neigh_get_dst(neigh));
	struct nl_addr *lladdr = rtnl_neigh_get_lladdr(neigh);
	uint32_t state = rtnl_neigh_get_state(neigh);
	uint32_t flags = rtnl_neigh_get_flags(neigh);
	nl_addr2str(lladdr, buf, sizeof(buf));
	uint8_t origin = (state == NUD_PERMANENT) ? 1 : 2;
	uint8_t is_router = ((flags & NTF_ROUTER) != 0);

	if (dm_add_object(answer) != RC_OK
	    || dm_add_address(answer, AVP_ADDRESS, VP_TRAVELPING, family, dst) != RC_OK
	    || dm_add_string(answer, AVP_STRING, VP_TRAVELPING, buf) != RC_OK
	    || dm_add_uint8(answer, AVP_ENUM, VP_TRAVELPING, origin) != RC_OK
	    || dm_add_uint8(answer, AVP_BOOL, VP_TRAVELPING, is_router) != RC_OK
	    || dm_finalize_group(answer) != RC_OK)
		return;
}

static void
add_addr_to_answer(struct nl_object *obj, void *data)
{
	char buf[32];
	DM2_REQUEST *answer = data;
	struct nl_addr *naddr = rtnl_addr_get_local((struct rtnl_addr *) obj);
	int family = nl_addr_get_family(naddr);
	unsigned int flags = rtnl_addr_get_flags((struct rtnl_addr *) obj);
	uint8_t origin = 0;
	uint8_t status = 4;

	logx(LOG_DEBUG, "IP: %s", nl_addr2str(naddr, buf, sizeof(buf)));

	if (flags & IFA_F_OPTIMISTIC)
		status = 7;
	else if (flags & IFA_F_TENTATIVE)
		status = 5;
	else if (flags & IFA_F_HOMEADDRESS)
		status = 0;
	else if (flags & IFA_F_DEPRECATED)
		status = 1;

	if (flags & IFA_F_PERMANENT)
		origin = 1;

	if (dm_add_object(answer) != RC_OK
	    || dm_add_address(answer, AVP_ADDRESS, VP_TRAVELPING, family, nl_addr_get_binary_addr(naddr)) != RC_OK
	    || dm_add_uint8(answer, AVP_UINT8, VP_TRAVELPING, nl_addr_get_prefixlen(naddr)) != RC_OK
	    || dm_add_uint8(answer, AVP_ENUM, VP_TRAVELPING, origin) != RC_OK
	    || dm_add_uint8(answer, AVP_ENUM, VP_TRAVELPING, status) != RC_OK
	    || dm_finalize_group(answer) != RC_OK)
		return;
}

uint32_t rpc_client_get_interface_state(void *ctx, const char *if_name, DM2_REQUEST *answer)
{
	int fd;
	FILE *fp;
	char line[1024];
	struct ifreq ifr;
	struct ethtool_cmd cmd;
	uint32_t rc;
	const char *dev;

	uint64_t rec_pkt = 0, rec_oct = 0, rec_err = 0, rec_drop = 0;
	uint64_t snd_pkt = 0, snd_oct = 0, snd_err = 0, snd_drop = 0;
	int scan_count;

	logx(LOG_DEBUG, "rpc_client_get_interface_state: %s", if_name);

	dev = if_name;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (fd == -1)
		return RC_ERR_MISC;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	ifr.ifr_name[IFNAMSIZ-1] = '\0';

	if ((rc = if_ioctl(fd, SIOCGIFINDEX, &ifr)) != RC_OK)
		return rc;
	if (ifr.ifr_ifindex == 0)
		ifr.ifr_ifindex = 2147483647;
	if ((rc = dm_add_int32(answer, AVP_INT32, VP_TRAVELPING, ifr.ifr_ifindex)) != RC_OK)
		return rc;

	if ((rc = if_ioctl(fd, SIOCGIFFLAGS, &ifr)) != RC_OK
	    || (rc = dm_add_uint32(answer, AVP_UINT32, VP_TRAVELPING, ifr.ifr_flags)) != RC_OK)
		return rc;

	if ((rc = if_ioctl(fd, SIOCGIFHWADDR, &ifr)) != RC_OK
	    || (rc = dm_add_raw(answer, AVP_BINARY, VP_TRAVELPING, &ifr.ifr_hwaddr, 6)) != RC_OK)
	    return rc;

	ifr.ifr_data = (void *)&cmd;
	cmd.cmd = ETHTOOL_GSET; /* "Get settings" */
	if ((rc = if_ioctl(fd, SIOCETHTOOL, &ifr)) != RC_OK) {
		if ((rc = dm_add_uint32(answer, AVP_UINT32, VP_TRAVELPING, 0)) != RC_OK)
			return rc;
	} else
		if ((rc = dm_add_uint32(answer, AVP_UINT32, VP_TRAVELPING, ethtool_cmd_speed(&cmd))) != RC_OK)
			return rc;

	if (!(fp = fopen("/proc/net/dev", "r")))
		return RC_ERR_MISC;

	if (!fgets(line, sizeof(line), fp)) /* ignore first line */
		logx(LOG_ERR, "Cannot parse /proc/net/dev");
	if (!fgets(line, sizeof(line), fp))
		logx(LOG_ERR, "Cannot parse /proc/net/dev");

	while (!feof(fp)) {
		char device[32];

		scan_count = fscanf(fp, " %32[^:]:%"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %*u %*u %*u %*u %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %*u %*u %*s",
				    device,
				    &rec_oct, &rec_pkt, &rec_err, &rec_drop,
				    &snd_oct, &snd_pkt, &snd_err, &snd_drop);
		if (scan_count == 9 && strcmp(dev, device) == 0)
			break;
	}
	fclose(fp);

	if ((rc = dm_add_object(answer)) != RC_OK
	    || (rc = dm_add_uint64(answer, AVP_UINT64, VP_TRAVELPING, rec_oct)) != RC_OK
	    || (rc = dm_add_uint64(answer, AVP_UINT64, VP_TRAVELPING, rec_pkt)) != RC_OK
	    || (rc = dm_add_uint64(answer, AVP_UINT64, VP_TRAVELPING, rec_err)) != RC_OK
	    || (rc = dm_add_uint64(answer, AVP_UINT64, VP_TRAVELPING, rec_drop)) != RC_OK
	    || (rc = dm_add_uint64(answer, AVP_UINT64, VP_TRAVELPING, snd_oct)) != RC_OK
	    || (rc = dm_add_uint64(answer, AVP_UINT64, VP_TRAVELPING, snd_pkt)) != RC_OK
	    || (rc = dm_add_uint64(answer, AVP_UINT64, VP_TRAVELPING, snd_err)) != RC_OK
	    || (rc = dm_add_uint64(answer, AVP_UINT64, VP_TRAVELPING, snd_drop)) != RC_OK
	    || (rc = dm_finalize_group(answer)) != RC_OK)
		return rc;

	/* read IP's from NL */

	int ifindex;
	struct nl_sock *socket = nl_socket_alloc();
	struct nl_cache *link_cache;
	struct nl_cache *addr_cache;
	struct nl_cache *neigh_cache;
	struct rtnl_link *link;
	struct rtnl_addr *addr_filter = NULL;
	struct rtnl_neigh *neigh_filter = NULL;
	int forward;
	uint32_t mtu;

	if (nl_connect(socket, NETLINK_ROUTE) < 0)
		return RC_ERR_MISC;

	if (rtnl_link_alloc_cache(socket, AF_UNSPEC, &link_cache) < 0
	    || rtnl_addr_alloc_cache(socket, &addr_cache) < 0
	    || rtnl_neigh_alloc_cache(socket, &neigh_cache) < 0) {
		nl_socket_free(socket);
		return RC_ERR_ALLOC;
	}

	rc = RC_OK;

	link = rtnl_link_get_by_name(link_cache, dev);
	ifindex = rtnl_link_get_ifindex(link);
	mtu = rtnl_link_get_mtu(link);
	if (mtu == 0 || mtu > 65535)
		mtu = 65535;

	addr_filter = rtnl_addr_alloc();
	rtnl_addr_set_ifindex(addr_filter, ifindex);

	/* IPv4 group */
	if ((rc = dm_add_object(answer)) != RC_OK)
		goto exit_nl;

	snprintf(line, sizeof(line), "/proc/sys/net/ipv4/conf/%s/forwarding", dev);
	sys_scan(line, "%u", &forward);

	logx(LOG_DEBUG, "IPv4 Forward: %d", forward);
	if ((rc = dm_add_uint8(answer, AVP_BOOL, VP_TRAVELPING, forward)) != RC_OK
	    || (rc = dm_add_uint32(answer, AVP_UINT32, VP_TRAVELPING, mtu)) != RC_OK)
		goto exit_nl;

	rtnl_addr_set_family(addr_filter, AF_INET);

	if ((rc = dm_add_object(answer)) != RC_OK)
		goto exit_nl;

	nl_cache_foreach_filter(addr_cache, (struct nl_object *) addr_filter, add_addr_to_answer, answer);
	if ((rc = dm_finalize_group(answer)) != RC_OK)
		goto exit_nl;

	neigh_filter = rtnl_neigh_alloc();
	rtnl_neigh_set_ifindex(neigh_filter, ifindex);

	rtnl_neigh_set_family(neigh_filter, AF_INET);

	if ((rc = dm_add_object(answer)) != RC_OK)
		goto exit_nl;
	nl_cache_foreach_filter(neigh_cache, (struct nl_object *) neigh_filter, add_neigh_to_answer, answer);
	if ((rc = dm_finalize_group(answer)) != RC_OK)
		goto exit_nl;

	/* IPv4 group */
	if ((rc = dm_finalize_group(answer)) != RC_OK)
		goto exit_nl;

	/* IPv6 group */
	if ((rc = dm_add_object(answer)) != RC_OK)
		goto exit_nl;

	snprintf(line, sizeof(line), "/proc/sys/net/ipv6/conf/%s/forwarding", dev);
	sys_scan(line, "%u", &forward);

	logx(LOG_DEBUG, "IPv6 Forward: %d", forward);
	if ((rc = dm_add_uint8(answer, AVP_BOOL, VP_TRAVELPING, forward)) != RC_OK
	    || (rc = dm_add_uint32(answer, AVP_UINT32, VP_TRAVELPING, mtu)) != RC_OK)
		goto exit_nl;

	rtnl_addr_set_family(addr_filter, AF_INET6);

	if ((rc = dm_add_object(answer)) != RC_OK)
		goto exit_nl;
	nl_cache_foreach_filter(addr_cache, (struct nl_object *) addr_filter, add_addr_to_answer, answer);
	if ((rc = dm_finalize_group(answer)) != RC_OK)
		goto exit_nl;

	rtnl_neigh_set_family(neigh_filter, AF_INET6);

	if ((rc = dm_add_object(answer)) != RC_OK)
		goto exit_nl;
	nl_cache_foreach_filter(neigh_cache, (struct nl_object *) neigh_filter, add_neigh_to_answer, answer);
	if ((rc = dm_finalize_group(answer)) != RC_OK)
		goto exit_nl;

	/* IPv6 group */
	if ((rc = dm_finalize_group(answer)) != RC_OK)
		goto exit_nl;

exit_nl:
	nl_cache_free(neigh_cache);
	nl_cache_free(addr_cache);
	nl_cache_free(link_cache);
	if (addr_filter) rtnl_addr_put(addr_filter);
	if (neigh_filter) rtnl_neigh_put(neigh_filter);
	nl_socket_free(socket);

	return rc;
}

static uint32_t
init_hostname(DMCONTEXT *dmCtx)
{
	uint32_t rc;
	char hostname[256];
	gethostname(hostname, sizeof(hostname));

	struct rpc_db_set_path_value set_value = {
		.path  = "system.hostname",
		.value = {
			.code = AVP_STRING,
			.vendor_id = VP_TRAVELPING,
			.data = hostname,
			.size = strlen(hostname)
		},
	};
	if ((rc = rpc_db_set(dmCtx, 1, &set_value, NULL)) != RC_OK)
		logx(LOG_WARNING, "Failed to report hostname, rc=%d.", rc);

	if ((rc = rpc_param_notify(dmCtx, NOTIFY_ACTIVE, 1, &set_value.path, NULL)) != RC_OK) {
		ev_break(dmCtx->ev, EVBREAK_ALL);
		CB_ERR_RET(rc, "Couldn't register PARAM NOTIFY request, rc=%d.", rc);
	}

	return RC_OK;
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

	if ((rc = rpc_db_set(dmCtx, nvalues, set_values, NULL)) != RC_OK)
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

static uint32_t
socketConnected(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *userdata __attribute__ ((unused)))
{
	uint32_t rc;

	if (event != DMCONFIG_CONNECTED) {
		ev_break(dmCtx->ev, EVBREAK_ALL);
	        CB_ERR_RET(RC_ERR_MISC, "Connecting socket unsuccessful.");
	}

	logx(LOG_DEBUG, "Socket connected.");

	if ((rc = rpc_startsession(dmCtx, CMD_FLAG_READWRITE, 0, NULL)) != RC_OK) {
		ev_break(dmCtx->ev, EVBREAK_ALL);
	        CB_ERR_RET(rc, "Couldn't register start session request, rc=%d.", rc);
	}

	logx(LOG_DEBUG, "Start session request registered.");

	if ((rc = rpc_register_role(dmCtx, "-state")) != RC_OK) {
		ev_break(dmCtx->ev, EVBREAK_ALL);
	        CB_ERR_RET(rc, "Couldn't register role, rc=%d.", rc);
	}
	logx(LOG_DEBUG, "Role registered.");

	if ((rc = rpc_subscribe_notify(dmCtx, NULL)) != RC_OK) {
		ev_break(dmCtx->ev, EVBREAK_ALL);
	        CB_ERR_RET(rc, "Couldn't register SUBSCRIBE NOTIFY request, rc=%d.", rc);
	}
	logx(LOG_DEBUG, "Notification subscription request registered.");

	if (init_hostname(dmCtx) != RC_OK)
		logx(LOG_WARNING, "Initial update of Hostname failed.");

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

	/*
	 * Requires the optional metropolis-pulsarlr Yang module.
	 */
	rc = rpc_recursive_param_notify(dmCtx, NOTIFY_ACTIVE, "pulsarlr", NULL);
	logx(LOG_INFO, "Registered recursive notification for \"pulsarlr\", rc=%d.", rc);

	/*
	 * Requires the optional metropolis-sparkplug Yang module.
	 */
	rc = rpc_recursive_param_notify(dmCtx, NOTIFY_ACTIVE, "sparkplug", NULL);
	logx(LOG_INFO, "Registered recursive notification for \"sparkplug\", rc=%d.", rc);

	/*
	 * Requires the optional metropolis-wwan Yang module.
	 */
	rc = rpc_recursive_param_notify(dmCtx, NOTIFY_ACTIVE, "wwan", NULL);
	logx(LOG_INFO, "Registered recursive notification for \"wwan\", rc=%d.", rc);

	/*
	 * NOTE: Beginning with the first asynchronous method call, we must no longer
	 * call synchronous versions.
	 */
	listSystemNtp(dmCtx);
	listSystemPtp(dmCtx);
	listSystemDns(dmCtx);
	listAuthentication(dmCtx);
	listInterfaces(dmCtx, IF_IP | IF_NEIGH);
	listAutoId(dmCtx);
	listSparkplug(dmCtx);
	listWWAN(dmCtx);

	return RC_OK;
}

void init_comm(struct ev_loop *loop)
{
	uint32_t rc;
	DMCONTEXT *ctx;

	if (!(ctx = dm_context_new())) {
	        logx(LOG_DEBUG, "Couldn't create socket context.");
	        return;
	}

	dm_context_init(ctx, loop, AF_INET, NULL, socketConnected, request_cb);

	/* connect */
	if ((rc = dm_connect_async(ctx)) != RC_OK) {
	        logx(LOG_DEBUG, "Couldn't register connect callback or connecting unsuccessful, rc=%d.", rc);
		dm_context_shutdown(ctx, DMCONFIG_ERROR_CONNECTING);
		dm_context_release(ctx);
	        return;
	}
	logx(LOG_DEBUG, "Connect callback registered.");
}

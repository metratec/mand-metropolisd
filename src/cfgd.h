/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __CFGD_H
#define __CFGD_H

#include <stdint.h>
#include <stdbool.h>

#include <sys/queue.h>
#include <sys/tree.h>
#include <ev.h>

struct ntp_servers {
	void *ctx;
	int enabled;
	int count;
	char **server;
};

struct auth_ssh_key {
	char *name;
	char *algo;
	char *data;
};

struct auth_ssh_key_list {
	void *ctx;
	int count;
	struct auth_ssh_key *ssh;
};

struct auth_user {
	char *name;
	char *password;
	struct auth_ssh_key_list ssh;
};

struct auth_list {
	void *ctx;
	int count;
	struct auth_user *user;
};

struct var_list {
	void *ctx;
	int count;
	void *data;
};

struct string_list {
	void *ctx;
	int count;
	char **s;
};

struct ipaddr {
	int af;
	char *address;
	char *value;
};

struct ip_list {
	void *ctx;
	int count;
	struct ipaddr *ip;
};

struct if_ip {
	uint8_t enabled;
	uint8_t forwarding;
	uint32_t mtu;
	struct ip_list addr;
	struct ip_list neigh;
	struct ip_list gateway;
};

struct if_dhcp {
	uint8_t enabled;
};

struct interface {
	char *name;
	unsigned int instance_id;
	unsigned int metric;

	struct if_ip ipv4;
	struct if_ip ipv6;
	struct if_dhcp dhcp;
};

struct interface_list {
	void *ctx;
	int count;
	struct interface *iface;

	unsigned int flags;
};

void set_ntp_server(const struct ntp_servers *servers);
void set_ptp_state(const char *state);
void set_mosquitto(const char *host, uint16_t port, bool tls,
                   const char *username, const char *password);
void set_wwan_4g(const char *apn, const char *pin,
                 const char *mode, const char *lte_mode,
                 const uint8_t *lte_bands);
void set_wifi(const char *ssid, const char *password,
              const char *security, const char *country);
void set_ex10(bool initial_setup, const char *mode);
void set_dns(const struct string_list *search, const struct string_list *servers);
void set_authentication(const struct auth_list *auth);
void set_if_addr(struct interface_list *info);
void set_if_neigh(struct interface_list *info);
void set_hostname(const char *str);
void set_value(char *path, const char *str);

char *quote_shell_arg(const char *arg);

#endif

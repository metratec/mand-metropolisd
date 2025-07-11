/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <inttypes.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <syslog.h>
#include <pwd.h>
#include <getopt.h>
#include <assert.h>

#define USE_DEBUG

#include <openssl/sha.h>

#include <ev.h>

#include <mand/logx.h>
#include <mand/binary.h>

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include "cfgd.h"
#include "comm.h"

/**
 * The prefix of the systemd config directory.
 * Since systemd files are managed by mand-metropolisd,
 * all files written by it can be in the volatile filesystem.
 */
#define SYSTEMD_PREFIX "/run/systemd"

#define CA_CERTIFICATES_PATH "/usr/share/ca-certificates/mozilla"

static const char _build[] = "build on " __DATE__ " " __TIME__ " with gcc " __VERSION__;

static int vsystem(const char *cmd);
static int vasystem(const char *fmt, ...) __attribute__ ((__format__ (__printf__, 1, 2)));

static int vsystem(const char *cmd)
{
	int rc = 0;
	int _errno;

	logx(LOG_INFO, "cmd=[%s]", cmd);

	errno = 0;
	rc = system(cmd);

	_errno = errno;
	logx(LOG_INFO, "cmd=[%s], rc=%d, error=%s", cmd, rc, strerror(_errno));
	errno = _errno;

	return rc;
}

static int vasystem(const char *fmt, ...)
{
	va_list args;
	char    buf[1024];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	return vsystem(buf);
}

/**
 * Escape a string such that it can be passed as a command line argument
 * in POSIX shell (double quotes).
 *
 * @param arg String to escape.
 * @returns Escaped string. Must be freed with free().
 */
char *quote_shell_arg(const char *arg)
{
	char *ret = malloc(strlen(arg)*2 + 1);
	if (!ret)
		return NULL;
	char *p = ret;
	while (*arg != '\0') {
		if (strchr("\"\\$`", *arg))
			*p++ = '\\';
		*p++ = *arg++;
	}
	*p = '\0';
	return ret;
}

void set_ntp_server(const struct ntp_servers *servers)
{
	FILE *fout;

	fout = fopen(SYSTEMD_PREFIX "/timesyncd.conf", "w");
	if (!fout) {
		/* FIXME: Error handling */
		return;
	}
	fprintf(fout, "# AUTOGENERATED BY %s\n"
	              "[Time]", PACKAGE_STRING);

	fputs("\nNTP =", fout);
	for (int i = 0; i < servers->count; i++) {
		fputc(' ', fout);
		fputs(servers->server[i], fout);
	}

	fclose(fout);

	/*
	 * This seems to be the only way to enforce a reload
	 * of the NTP configuration.
	 */
	vsystem("timedatectl set-ntp 0");
	vasystem("timedatectl set-ntp %d", servers->enabled);
}

void set_ptp_state(const char *state)
{
	FILE *fout;
	int is_master = !strcmp(state, "master");

	fout = fopen("/etc/ptp4l.conf", "w");
	if (!fout) {
		/* FIXME: Error handling */
		return;
	}

	/*
	 * The "master" state is currently interpreted as
	 * 'we may become a master'. There does not seem to be
	 * a way to guarantee that one particular device becomes
	 * the master.
	 */
	fprintf(fout, "# AUTOGENERATED BY %s\n"
	              "[global]\n"
	              "priority1 %d\n"
	              "[eth0]\n",
	        PACKAGE_STRING, is_master ? 128 : 255);

	fclose(fout);

	/*
	 * NOTE: We could start `phc2sys -a -rr` to synchronize
	 * the PTP and system clocks depending on whether this
	 * device is a master or slave.
	 * Unfortunately, since there is no guarantee to become a master,
	 * we must prevent the system clock which may be manually or NTP-synced
	 * to be overwritten by phc2sys.
	 */
	fout = fopen("/etc/default/phc2sys", "w");
	if (!fout) {
		/* FIXME: Error handling */
		return;
	}

	fprintf(fout, "# AUTOGENERATED BY %s\n"
	              "PHC2SYS_EXTRA_ARGS=\"-w -s %s -c %s\"\n",
	        PACKAGE_STRING,
	        is_master ? "CLOCK_REALTIME" : "eth0",	/* master clock */
	        is_master ? "eth0" : "CLOCK_REALTIME"	/* slave clock */);

	fclose(fout);

	vasystem("systemctl %s ptp4l phc2sys",
	         !strcmp(state, "disabled") ? "stop" : "reload-or-restart");
}

void set_dns(const struct string_list *search, const struct string_list *servers)
{
	FILE *fout;

	fout = fopen(SYSTEMD_PREFIX "/resolved.conf", "w");
	if (!fout) {
		/* FIXME: Error handling */
		return;
	}
	fprintf(fout, "# AUTOGENERATED BY %s\n"
	              "[Resolve]", PACKAGE_STRING);

	fputs("\nDNS =", fout);
	for (int i = 0; i < servers->count; i++) {
		fputc(' ', fout);
		fputs(servers->s[i], fout);
	}

	/*
	 * FIXME: The "Domains" key is not supported by systemd 219.
	 * The only other way to specify them would be to include
	 * them in the .../systemd/network files.
	 * However, in systemd 219, it is not possible to use "drop-in"
	 * files to extend the config written by set_if_addr().
	 * Therefore we disable search-domain support for the time being.
	 */
	fputs("\n#Domains =", fout);
	for (int i = 0; i < search->count; i++) {
		fputc(' ', fout);
		fputs(search->s[i], fout);
	}

	fclose(fout);

	vsystem("systemctl reload-or-restart systemd-resolved");
}

#if 0

static void
set_ssh_keys(const char *name, const struct auth_ssh_key_list *list)
{
	int i;
	FILE *fout;
	char *auth_file;

	if (strcmp(name, "netconfd") == 0) {
		auth_file = strdup("/etc/netconf/authorized_keys");
	} else {
		struct passwd *pw;

		if (!(pw = getpwnam(name)))
			return;

		if (!pw->pw_dir || list->count == 0)
			return;

		if (asprintf(&auth_file, "%s/.ssh/authorized_keys", pw->pw_dir) < 0)
			return;

		vasystem("mkdir -p %s/.ssh", pw->pw_dir);
	}

	if (!(fout = fopen(auth_file, "w")))
		goto exit;

	for (i = 0; i < list->count; i++) {
		logx(LOG_INFO, "  Key: %s %s %s", list->ssh[i].algo, list->ssh[i].data, list->ssh[i].name);
		fprintf(fout, "%s %s %s\n", list->ssh[i].algo, list->ssh[i].data, list->ssh[i].name);
	}
	fclose(fout);

 exit:
	free(auth_file);
}

#endif

void set_authentication(const struct auth_list *auth)
{
	FILE *file = fopen("/run/pyot-engine-users.json", "w");
	if (!file) {
		/* FIXME: Error handling */
		return;
	}

	fputs("{\"users\": [", file);

	logx(LOG_DEBUG, "Users: %d", auth->count);
	for (int i = 0; i < auth->count; i++) {
		if (!*auth->user[i].name || strpbrk(auth->user[i].name, "\\\"") ||
		    !*auth->user[i].password)
			continue;

		logx(LOG_INFO, "User: %s, pass: %s, ssh: %d",
		     auth->user[i].name, auth->user[i].password, auth->user[i].ssh.count);

		unsigned char hash[SHA256_DIGEST_LENGTH];
		SHA256((unsigned char *)auth->user[i].password, strlen(auth->user[i].password), hash);

		fprintf(file, "%s{\"username\": \"%s\", \"password\": \"",
		        i == 0 ? "\n" : ",\n", auth->user[i].name);
		for (int i = 0; i < sizeof(hash); i++)
			fprintf(file, "%02x", hash[i]);
		fprintf(file, "\", \"roles\": [\"%s\"]}",
		        !strcmp(auth->user[i].name, "admin") ? "admin" : "user");
	}

	fputs("\n]}", file);
	fclose(file);

	/*
	 * NOTE: Not every Metropolis-based device has pyot-engine
	 * and the existance of the user-database does not correspond with the
	 * existance of pyot-engine.
	 */
	//vsystem("systemctl try-reload-or-restart pyot-engine");
}

static inline const char *
systemd_ip_setting(int ipv4, int ipv6)
{
	if (ipv4 && ipv6)
		return "yes";
	else if (ipv4)
		return "ipv4";
	else if (ipv6)
		return "ipv6";

	return "no";
}

void set_if_addr(struct interface_list *info)
{
	/*
	 * NOTE: It does not seem to be possible to configure multiple
	 * interfaces in a single *.network file, so we create one
	 * file per interface.
	 */
	vsystem("rm -rf " SYSTEMD_PREFIX "/network");
	vsystem("mkdir -p " SYSTEMD_PREFIX "/network");

	for (int i = 0; i < info->count; i++) {
		struct interface *iface = info->iface + i;
		char systemd_cfg[PATH_MAX];
		FILE *fout;
		const char *dhcp_setting;
		uint32_t mtu;

		snprintf(systemd_cfg, sizeof(systemd_cfg),
		         "%s/network/%s.network",
		         SYSTEMD_PREFIX, iface->name);
		fout = fopen(systemd_cfg, "w");
		if (!fout) {
			/* FIXME: Error handling? */
			return;
		}

		/*
		 * NOTE: The Metropolis network configuration can
		 * be only in two states: either static or DHCP+AutoIP
		 * Thus we do not write the static addresses since
		 * that would be interpreted as a fallback by Systemd
		 * in case that dynamic address assignment does not work.
		 * Enforcing this here means that the UI and any external
		 * configuration is consistent.
		 *
		 * FIXME: The current model does NOT allow DHCP and static
		 * addressing to be configured independently on IPv4/IPv6.
		 * This is a restriction of the IETF DHCP yang module which
		 * would have to be replaced with a custom Metropolis extension.
		 */
		dhcp_setting = systemd_ip_setting(iface->ipv4.enabled && iface->dhcp.enabled,
			                          iface->ipv6.enabled && iface->dhcp.enabled);
		fprintf(fout, "# AUTOGENERATED BY %s\n"
		              "[Match]\n"
		              "Name=%s\n"
		              "[Network]\n"
		              "DHCP=%s\n"
		              "LinkLocalAddressing=%s\n"
		              "IPForward=%s\n",
		        PACKAGE_STRING, iface->name,
		        dhcp_setting, dhcp_setting,
		        systemd_ip_setting(iface->ipv4.enabled && iface->ipv4.forwarding,
		                           iface->ipv6.enabled && iface->ipv6.forwarding));

		if (iface->dhcp.enabled) {
			fprintf(fout, "[DHCP]\n"
			              "RouteMetric=%u\n", iface->metric);
		} else {
			if (iface->ipv4.enabled) {
				for (int j = 0; j < iface->ipv4.addr.count; j++)
					fprintf(fout, "[Address]\n"
					              "Address=%s/%s\n",
					        iface->ipv4.addr.ip[j].address, iface->ipv4.addr.ip[j].value);
			}

			if (iface->ipv6.enabled) {
				for (int j = 0; j < iface->ipv6.addr.count; j++)
					fprintf(fout, "[Address]\n"
					              "Address=%s/%s\n",
					        iface->ipv6.addr.ip[j].address, iface->ipv6.addr.ip[j].value);
			}

			if (iface->ipv4.enabled || iface->ipv6.enabled) {
				fprintf(fout, "[Route]\n"
				              "Metric=%u\n", iface->metric);

				if (iface->ipv4.enabled) {
					for (int j = 0; j < iface->ipv4.gateway.count; j++)
						fprintf(fout, "Gateway=%s\n", iface->ipv4.gateway.ip[j].address);
				}

				if (iface->ipv6.enabled) {
					for (int j = 0; j < iface->ipv6.gateway.count; j++)
						fprintf(fout, "Gateway=%s\n", iface->ipv6.gateway.ip[j].address);
				}
			}
		}

		/*
		 * The data model supports distinct MTUs for IPv4 and IPv6
		 * while Systemd only allows us to configure one MTU per link.
		 * Thus we take the minimum of both MTUs.
		 */
		mtu = iface->ipv6.mtu && iface->ipv4.mtu > iface->ipv6.mtu
			? iface->ipv6.mtu : iface->ipv4.mtu;
		if (mtu)
			fprintf(fout, "[Link]\n"
			              "MTUBytes=%u\n", mtu);

		fclose(fout);
	}

	vsystem("systemctl reload-or-restart systemd-networkd");
}

void set_if_neigh(struct interface_list *info)
{
	vsystem("ip neigh flush nud permanent");

	for (int i = 0; i < info->count; i++) {
		struct interface *iface = info->iface + i;

		for (int j = 0; j < info->iface[i].ipv4.neigh.count; j++)
			vasystem("ip neigh replace %s lladdr %s nud permanent dev %s",
			         iface->ipv4.neigh.ip[j].address, iface->ipv4.neigh.ip[j].value,
			         iface->name);

		for (int j = 0; j < iface->ipv6.neigh.count; j++)
			vasystem("ip neigh replace %s lladdr %s nud permanent dev %s",
			         iface->ipv6.neigh.ip[j].address, iface->ipv6.neigh.ip[j].value,
			         iface->name);
	}
}

void set_mosquitto(const char *host, uint16_t port, bool tls,
                   const char *username, const char *password)
{
	if (!host || !*host) {
		logx(LOG_WARNING, "Missing hostname, will not start Mosquitto");
		vsystem("systemctl stop mosquitto-metropolis");
		return;
	}

	if (!username || !*username || strpbrk(username, " \t\n\r")) {
		logx(LOG_WARNING, "Invalid username, will not start Mosquitto");
		vsystem("systemctl stop mosquitto-metropolis");
		return;
	}

	FILE *fout = fopen("/run/mosquitto.conf", "w");
	if (!fout) {
		logx(LOG_ERR, "Cannot open mosquitto.conf for writing: %s",
		     strerror(errno));
		return;
	}

	fprintf(fout,
	        "# AUTOGENERATED BY %s\n"
	        "user root\n"
	        "pid_file /run/mosquitto.pid\n"
	        /*
	         * By default, we must not listen on ANY since client connections
	         * are not authenticated.
	         * As a debug feature, this is very handy, though.
	         */
#ifdef DEBUG_TWEAKS
	        "bind_address 0.0.0.0\n"
#else
	        "bind_address localhost\n"
#endif
		"allow_anonymous true\n"
	        "connection ACS\n"
	        "address %s:%u\n"
	        /*
	         * NOTE: The remote end subscribes for messages only on our group_id and
	         * eon_node_id.
	         * Therefore we don't have to include them in the "topic" rule below.
	         * Should we have to check for "topic" names someday, we have to find out
	         * how to escape spaces (check the Mosquitto source code).
	         */
	        "topic spBv1.0/+/NBIRTH/# out 1\n"
	        "topic spBv1.0/+/DBIRTH/# out 1\n"
	        "topic spBv1.0/+/NDATA/# out 1\n"
	        "topic spBv1.0/+/DDATA/# out 1\n"
	        "topic spBv1.0/+/NDEATH/# out 1\n"
	        "topic spBv1.0/+/DDEATH/# out 1\n"
	        /*
	         * NOTE: Due to a bug in the metraTec cloud's MQTT broker, we cannot
	         * subscribe for everything containing the eon_node_id,
	         * We therefore include it in the topic name.
	         * This is safe since it is validated and must not contain any spaces.
	         */
	        "topic spBv1.0/+/NCMD/%s/# in 2\n"
	        "topic spBv1.0/+/DCMD/%s/# in 2\n"
	        /*
	         * We assume that we can only receive STATE messages from the backend server
	         * we're bridging to.
	         */
	        "topic STATE/# in 1\n"
	        /*
	         * This is set to publish notification messages to the local and
		 * remote broker about the bridge connection.
		 * Retained messages would be published to '$SYS/broker/connection/<remote_clientid>/state'.
		 * This topic seems to be broken, so it is set with notification_topic.
		 * Bridge protocol and try_private has to be set to inform the broker,
		 * that a bridge is connecting.
		 *
		 * See https://github.com/vernemq/vernemq/issues/1306 for more informations.
	         */
	        "notifications true\n"
	        "notification_topic CLIENTS/%s/state\n"
	        "bridge_protocol_version mqttv311\n"
	        "try_private false\n"
	        "remote_clientid %s\n"
	        "remote_username %s\n",
	        PACKAGE_STRING, host, port,
	        username, username, username, username, username);
	if (password && *password && !strpbrk(password, "\n\r"))
		fprintf(fout, "remote_password %s\n", password);
	if (tls)
		fprintf(fout, "bridge_capath %s\n", CA_CERTIFICATES_PATH);

	fclose(fout);

	/*
	 * Apparently, reloading Mosquitto is insufficient to re-establish
	 * the bridge connection.
	 */
	vsystem("systemctl restart mosquitto-metropolis");
}

static inline bool validate_at_param(const char *str)
{
	return str && !strpbrk(str, "\n\r\",");
}

void set_wwan_4g(const char *apn, const char *pin, const char *mode, const char *lte_mode,
                 const uint8_t *lte_bands)
{
	/*
	 * NOTE: It is apparently not possible to escape special characters in
	 * AT commands and mand does also not allow us to prevent sets with invalid characters.
	 * Therefore we guard against "AT command insertion" by aborting.
	 */
	if (!validate_at_param(apn) || (pin && *pin && !validate_at_param(pin))) {
		logx(LOG_ERR, "APN and/or PIN are malformed");
		return;
	}

	FILE *fout = fopen("/run/quectel-chat-connect", "w");
	if (!fout) {
		logx(LOG_ERR, "Cannot open quectel-chat-connect for writing: %s",
		     strerror(errno));
		return;
	}

	unsigned int mode_id = 0;

	if (!strcmp(mode, "automatic"))
		mode_id = 0;
	else if (!strcmp(mode, "gsm"))
		mode_id = 1;
	else if (!strcmp(mode, "lte"))
		mode_id = 3;

#if 0
	unsigned int lte_mode_id = 3;

	if (!strcmp(lte_mode, "cat-m"))
		lte_mode_id = 1;
	else if (!strcmp(lte_mode, "nb-iot"))
		lte_mode_id = 2;
	else if (!strcmp(lte_mode, "all"))
		lte_mode_id = 3;
#endif

	fprintf(fout,
	        "# AUTOGENERATED BY %s\n"
	        "ABORT 'NO CARRIER'\n"
	        "ABORT 'NO DIALTONE'\n"
	        "ABORT 'ERROR'\n"
	        "ABORT 'NO ANSWER'\n"
	        "ABORT 'BUSY'\n"
	        "TIMEOUT 5\n"
	        "'' AT\n"
	        "OK ATE0\n"
	        "OK AT+CSQ\n"
	        "OK AT+CPIN?\n"
	        "OK AT+COPS?\n"
	        "OK AT+CGREG?\n"
	        "OK ATZ\n"
	        /*
	         * FIXME: What if the provider supports only IPV6?
	         * Perhaps we should support a wwan-4g.ip-mode setting.
	         */
	        "OK AT+CGDCONT=1,\"IP\",\"%s\",,0,0\n"
	        "OK AT+QCFG=\"nwscanmode\",%u\n",
	        PACKAGE_STRING, apn, mode_id);
	if (pin && *pin)
		fprintf(fout, "OK AT+CPIN=%s\n", pin);
	if (lte_bands) {
		uint64_t band_mask = 0;
		for (int i = 0; lte_bands[i] != 0; i++)
			band_mask |= (1 << (lte_bands[i]-1));
		fprintf(fout, "OK AT+QCFG=\"band\",FFFF,%" PRIx64 "\n", band_mask);
	}
	fputs("OK ATD*99#\n"
	      "CONNECT\n", fout);

	fclose(fout);

	vsystem("systemctl restart metropolis-wwan-4g");
}

void set_wifi(const char *ssid, const char *password,
              const char *security, const char *country)
{
	size_t password_len = strlen(password);

	if (strcmp(security, "none") != 0 &&
	    (8 > password_len || password_len > 63)) {
		logx(LOG_WARNING, "Invalid Wi-Fi passphrase");
		vsystem("systemctl stop metropolis-wifi");
		return;
	}

	FILE *fout = fopen("/run/wpa_supplicant.conf", "w");
	if (!fout) {
		logx(LOG_ERR, "Cannot open wpa_supplicant.conf for writing: %s",
		     strerror(errno));
		return;
	}

	fputs("# AUTOGENERATED BY " PACKAGE_STRING "\n", fout);

	/*
	 * NOTE: We don't currently limit the country codes that can be set.
	 * This might result in invalid configurations, but the worst
	 * that can happen is that metropolis-wifi is restarted indefinitely.
	 */
        if (country && strlen(country) == 2)
		fprintf(fout, "country=%s\n", country);

	if (strlen(ssid) > 1) {
		fprintf(fout,
		        "network={\n"
		        "key_mgmt=%s\n"
		        "scan_ssid=1\n"
		        "ssid=",
		        !strcmp(security, "wpa2-personal") ? "WPA-PSK" : "NONE");
		for (const char *p = ssid; *p; p++)
			fprintf(fout, "%02X", *p);
		fputs("\n", fout);

		if (!strcmp(security, "none")) {
			fputs("}", fout);
			fclose(fout);
		} else {
			fclose(fout);

			char *ssid_quoted = quote_shell_arg(ssid);
			char *password_quoted = quote_shell_arg(password);
			assert(ssid_quoted != NULL && password_quoted != NULL);

			/*
			 * NOTE: SSIDs and passwords have a maximum length, so
			 * vasystem() will definitely work here.
			 */
			vasystem("wpa_passphrase \"%s\" \"%s\" | tail -n -2 >>/run/wpa_supplicant.conf",
			         ssid_quoted, password_quoted);

			free(password_quoted);
			free(ssid_quoted);
		}
	} else {
		fclose(fout);
	}

	vsystem("systemctl restart metropolis-wifi");
}

/*
 * Multiple apps can be implemented in the future.
 * That's way we already get the `name` passed.
 * Should we need multiple apps, this could be passed to a service template.
 */
void set_app(const char *name, bool enabled)
{
	vasystem("systemctl %s metropolis-app", enabled ? "start" : "stop");
}

void set_hostname(const char *str)
{
	if (sethostname(str, strlen(str))) {
		logx(LOG_ERR, "Cannot set hostname: %m");
		return;
	}

	/*
	 * NOTE: Reloading the avahi-daemon is not enough to pick up new
	 * host names.
	 */
	vsystem("systemctl restart avahi-daemon");
}

void set_value(char *path, const char *str)
{
	logx(LOG_DEBUG, "Parameter \"%s\" changed to \"%s\"", path, str);

	if (strcmp(path, "system.hostname") == 0) {
		set_hostname(str);
	}
}

static void sig_usr1(EV_P_ ev_signal *w, int revents)
{
}

static void sig_usr2(EV_P_ ev_signal *w, int revents)
{
	logx_level = logx_level == LOG_DEBUG ? LOG_INFO : LOG_DEBUG;
}

static void sig_pipe(EV_P_ ev_signal *w, int revents)
{
	logx(LOG_DEBUG, "sig_pipe");
}

static void sig_term(EV_P_ ev_signal *w, int revents)
{
	const char *signal_name = w->data;

	logx(LOG_INFO, "Signal %s received. Shutting down gracefully...", signal_name);
	ev_break(EV_A_ EVBREAK_ALL);

	/*
	 * Stopping the signal watcher restores the default
	 * signal action.
	 * This is important since it allows program termination even if
	 * graceful shutdown is broken.
	 */
	ev_signal_stop(EV_A_ w);
}

static void usage(void)
{
	printf("cfgd, Version: .....\n\n"
	       "Usage: cfg [OPTION...]\n\n"
	       "Options:\n\n"
	       "  -h                        this help\n"
	       "  -l, --log=IP              write log to syslog at this IP\n"
	       "  -x                        debug logging\n\n");

	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	ev_signal signal_usr1, signal_usr2, signal_pipe;
	ev_signal signal_hup, signal_int, signal_term;

	int c;

	logx_level = LOG_INFO;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"log",       1, 0, 'l'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hl:x",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage();
			break;

		case 'l': {
			struct in_addr addr;

			if (inet_aton(optarg, &addr) == 0) {
				fprintf(stderr, "Invalid IP address: '%s'\n", optarg);
				exit(EXIT_FAILURE);
			} else
				logx_remote(addr);
			break;
		}

		case 'x':
			logx_level = LOG_DEBUG;
			break;

		default:
			printf("?? getopt returned character code 0%o ??\n", c);
		}
	}

	logx_open(basename(argv[0]), LOG_CONS | LOG_PID | LOG_PERROR, LOG_DAEMON);

	ev_signal_init(&signal_usr1, sig_usr1, SIGUSR1);
	ev_signal_start(EV_DEFAULT_ &signal_usr1);

	ev_signal_init(&signal_usr2, sig_usr2, SIGUSR2);
	ev_signal_start(EV_DEFAULT_ &signal_usr2);

	ev_signal_init(&signal_pipe, sig_pipe, SIGPIPE);
	ev_signal_start(EV_DEFAULT_ &signal_pipe);

	/*
	 * Register termination signal watchers.
	 * This is important to perform graceful shutdowns when being
	 * supervised (e.g. by systemd).
	 * Also, cleaning up on exit eases debugging using Valgrind/memcheck.
	 */
	ev_signal_init(&signal_hup, sig_term, SIGHUP);
	signal_hup.data = "SIGHUP";
	ev_signal_start(EV_DEFAULT_ &signal_hup);
	ev_signal_init(&signal_int, sig_term, SIGINT);
	signal_int.data = "SIGINT";
	ev_signal_start(EV_DEFAULT_ &signal_int);
	ev_signal_init(&signal_term, sig_term, SIGTERM);
	signal_term.data = "SIGTERM";
	ev_signal_start(EV_DEFAULT_ &signal_term);

	init_comm(EV_DEFAULT);

	logx(LOG_NOTICE, "startup %s %s", PACKAGE_STRING, _build);

	ev_run(EV_DEFAULT, 0);

	return 0;
}

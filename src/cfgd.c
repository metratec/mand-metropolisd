/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include <stdlib.h>
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

#define USE_DEBUG

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

void set_ntp_server(const struct ntp_servers *servers)
{
	FILE *fout;

	fout = fopen("/etc/systemd/timesyncd.conf", "w");
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
	 * In case systemd-timesyncd is already running,
	 * we make sure it reloads its configuration.
	 */
	vsystem("systemctl stop systemd-timesyncd");
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

	fout = fopen("/etc/systemd/resolved.conf", "w");
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
	 * them in the /etc/systemd/network files.
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

#else

static void
set_ssh_keys(const char *name, const struct auth_ssh_key_list *list)
{
}

#endif

void set_authentication(const struct auth_list *auth)
{
	int i;

	logx(LOG_DEBUG, "Users: %d", auth->count);
	for (i = 0; i < auth->count; i++) {
		logx(LOG_INFO, "User: %s, pass: %s, ssh: %d",
		     auth->user[i].name, auth->user[i].password, auth->user[i].ssh.count);

		set_ssh_keys(auth->user[i].name, &auth->user[i].ssh);
	}
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
	vsystem("rm -f /etc/systemd/network/*.network");

	for (int i = 0; i < info->count; i++) {
		struct interface *iface = info->iface + i;
		char systemd_cfg[PATH_MAX];
		FILE *fout;
		const char *dhcp_setting;
		uint32_t mtu;

		snprintf(systemd_cfg, sizeof(systemd_cfg),
		         "/etc/systemd/network/%s.network", iface->name);
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

		if (iface->ipv4.enabled && !iface->dhcp.enabled) {
			for (int j = 0; j < iface->ipv4.addr.count; j++)
				fprintf(fout, "Address=%s/%s\n",
				        iface->ipv4.addr.ip[j].address, iface->ipv4.addr.ip[j].value);
		}

		if (iface->ipv6.enabled && !iface->dhcp.enabled) {
			for (int j = 0; j < iface->ipv6.addr.count; j++)
				fprintf(fout, "Address=%s/%s\n",
				        iface->ipv6.addr.ip[j].address, iface->ipv6.addr.ip[j].value);
		}

		fputs("[Route]\n", fout);

		if (iface->ipv4.enabled && !iface->dhcp.enabled) {
			for (int j = 0; j < iface->ipv4.gateway.count; j++)
				fprintf(fout, "Gateway=%s\n", iface->ipv4.gateway.ip[j].address);
		}

		if (iface->ipv6.enabled && !iface->dhcp.enabled) {
			for (int j = 0; j < iface->ipv6.gateway.count; j++)
				fprintf(fout, "Gateway=%s\n", iface->ipv6.gateway.ip[j].address);
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

void set_value(char *path, const char *str)
{
	logx(LOG_DEBUG, "Parameter \"%s\" changed to \"%s\"", path, str);

	if (strcmp(path, "system.hostname") == 0) {
		/*
		 * FIXME FIXME FIXME: This is vulnerable to Shell injections.
		 * FIXME FIXME: hostnamectl currently broken on Metropolis
		 */
#if 0
		vasystem("hostnamectl set-hostname '%s'", str);
#endif
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

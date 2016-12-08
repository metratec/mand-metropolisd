# mand Metropolis config agent

mand-metropolisd is a configration agent for mand that applies value changes to a
Metropolis-based operating system though systemd and report statistic and runtime
state values back to mand though mand'd dmconfig RPC API.

mand-metropolisd is a fork of [mand-cfgd](https://github.com/opencpe/mand-cfgd).

It currently implements a limited set of values from IETF YANG NETCONF models for
the /system, /system-state, /interfaces and /interfaces-state sub-trees.

For applying and changing configutation values, currently systemd command-line tools
are used.
For reading interface configuration and status values, direct Linux system calls, procfs,
sysfs and netlink API's are used.

# Building and Install

## Requirements

- GNU make
- autotools
- autoconf
- libtool
- shtool
- gcc >= 4.7
- libev
- libtalloc
- libnl and libnl-route

## Build and Install

* rebuild automake and friends

	./autogen.sh

* configure

	./configure --prefix=/usr

* build and install

	make
	make install

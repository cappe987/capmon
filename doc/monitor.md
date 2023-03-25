<!---
SPDX-License-Identifier: GPL-2.0-only
SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>
-->

# Capmon - monitor mode
Monitor mode is a secondary mode that will output all capability checks that
match the given filters, similar to that of `tcpdump`. It is left in for
reasons that it may be useful to someone wanting to do exactly this. The
primary purpose of Capmon is to find the capabilities of a single command and
the primary mode is great for that. Though, primary mode can't handle zombie
processes or otherwise detached processes that monitor mode could. Firefox is
such an example.

Start monitoring capability checks.
```
capmon -m
```

Filter by process name. Supports POSIX-Extended Regular Expressions (tip: use
quotation marks to avoid the shell interpreting as globbing).
```
capmon -m tcpdump trafgen
```

Filter by process ID
```
capmon -m -p 13424
```

Filter by capability
```
capmon -m -c CAP_NET_RAW
```

Summary mode. On exit, output a summary of which capabilities each process has
accessed. Either grouped by process name or by pid.
```
capmon -m -s pid
capmon -m -s name
```

Listen to ALL capability checks. By default it only listens to the functions
`ns_capable` and `capable_wrt_inode_uidgid`. This listens directly to the
`cap_capable` function. This flag is available in primary mode as well.
```
capmon -m -a
```

All the above arguments can be combined freely. Multiple filters can be used.
Filters of the same type are treated as `OR` operations. Filters of different
types are treated as `AND` operations. For example, the command
```
capmon -m tcpdump trafgen -c CAP_NET_RAW
```
is interpreted as
```
(name:tcpdump OR name:trafgen) AND (capability:CAP_NET_RAW)
```

## Example: combining arguments

The example below displays only `tcpdump` and `trafgen` commands, will listen
to ALL capability checks, will do a summary at the end based on the names
(which will only be tcpdump and trafgen), and will only display if the
capability being checked is also `CAP_NET_RAW` or `CAP_NET_ADMIN`. So it has to
belong to either of the names AND be one of those two capabilities.
```
capmon -m tcpdump trafgen -a -s name -c CAP_NET_RAW -c CAP_NET_ADMIN
```
This particular combination may not be very useful, but it shows how you can
combine the arguments.


<!---
SPDX-License-Identifier: GPL-2.0-only
SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>
-->

# capmon - Linux Capabilities monitor

Monitor when processes check
[capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) to
find out what they require.

If you want to run `ip netns add some_name` without sudo you would start `capmon`
and try to run the command (without sudo). The first time you will notice that
it shows `CAP_SYS_ADMIN` in `capmon` for the `ip` command. Resolve that
by giving yourself and the program the capability and run the command again.
This time you will notice that `capmon` first outputs `CAP_SYS_ADMIN` and
then `CAP_DAC_OVERRIDE` for `ip`, and the command will fail. After also adding
`CAP_DAC_OVERRIDE` you can now use `ip netns` commands without sudo.

> Note: I do not know much about how capabilities works or how it's used in the
> kernel. Capmon might show more than required. I do not yet know why the
> kernel does all the extra checks.

`capmon` itself requires `CAP_DAC_OVERRIDE` to run.

# Installation
```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
sudo make install
```

# Usage
Start monitoring capability checks.
```
capmon
```

Filter by process name. (todo: support regex)
```
capmon tcpdump trafgen
```

Filter by process ID
```
capmon -p 13424
```

Filter by capability
```
capmon -c CAP_NET_RAW
```

Summary mode. On exit, output a summary of which capabilities each process has
accessed. Either grouped by process name or by pid.
```
capmon -s pid
capmon -s name
```

Listen to ALL capability checks. By default it only listens to the functions
`ns_capable` and `capable_wrt_inode_uidgid`. This listens directly to the
`cap_capable` function.
```
capmon -a
```

All the above arguments can be combined freely. Multiple filters can be used.
Filters of the same type are treated as `OR` operations. Filters of different
types are treated as `AND` operations. For example, the command
```
capmon tcpdump trafgen -c CAP_NET_RAW
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
capmon tcpdump trafgen -a -s name -c CAP_NET_RAW -c CAP_NET_ADMIN
```
This particular combination may not be very useful, but it shows how you can
combine the arguments.

## Running in background

Start or stop monitoring in the background. Can only be combined with `-a`.
After enabling it you can view and filter the output by running `capmon` as
shown above.
```
capmon --enable
capmon --disable
```

# To-do list
- Check for possible out of range indexing in the code
- Filter out capmons own checks on startup?
- Return value of cap check?

# Issues
- Killing it with SIGKILL will leave the kprobes active. Can be removed with
  `capmon --disable`.
- If starting with sudo, it will not properly exit if sudo timeout is reached
  (i.e. when you need to enter your password again). `Interrupted system call`.
  But will still remove the probes. Why?
- To get correct comm names (process names) you can do `sudo sh` and run the commands. 
  Otherwise, the desktop manager may take over the name.
- Note that some kernel functions will call `cap_capable` directly, instead of
  going through the other functions. Or they use some other less-common path.



# Notes on ktraceprobes


## Create kprobe
echo 'p:myprobe ns_capable cap=$arg2 comm=$comm' > /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/events/kprobes/myprobe/enable

## Output log
cat /sys/kernel/debug/tracing/trace

## Remove
echo 0 > /sys/kernel/debug/tracing/events/kprobes/myprobe/enable
echo -:myprobe >> /sys/kernel/debug/tracing/kprobe_events

## Clear log
echo 0 > /sys/kernel/debug/tracing/trace

## Clear all kprobes
echo > /sys/kernel/debug/tracing/kprobe_events




echo 'p:capmon_ns ns_capable cap=$arg2 comm=$comm' >> /sys/kernel/debug/tracing/kprobe_events
echo 'p:capmon_inode capable_wrt_inode_uidgid cap=$arg3 comm=$comm' >> /sys/kernel/debug/tracing/kprobe_events

echo 1 > /sys/kernel/debug/tracing/events/kprobes/capmon_inode/enable
echo 1 > /sys/kernel/debug/tracing/events/kprobes/capmon_ns/enable

cat /sys/kernel/debug/tracing/trace

echo 0 > /sys/kernel/debug/tracing/events/kprobes/capmon_ns/enable
echo 0 > /sys/kernel/debug/tracing/events/kprobes/capmon_inode/enable

echo -:capmon_ns >> /sys/kernel/debug/tracing/kprobe_events
echo -:capmon_inode >> /sys/kernel/debug/tracing/kprobe_events

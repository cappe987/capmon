# Capdump - Linux Capabilities monitor

Monitor when processes check capabilities to find out what they need.



# Usage

Create kprobes and start monitor. Removes kprobes on graceful exit. Killing it
with SIGKILL will leave the kprobes and they must be removed with `capdump
--disable`.
```
capdump
```

Filter by process name (in this case, the name "tcpdump"). Optional, but should
always be the last argument. Supports regex.
```
capdump tcpdump
```

Filter by process ID
```
capdump -p 13424
```

Filter by capability
```
capdump -c CAP_NET_RAW
```

Summary mode. On exit, output a summary of which capabilities each process has
accessed. Either grouped by process name or by pid.
```
capdump -s pid
capdump -s comm
```

Listen to ALL capability checks.
```
capdump -a
```

All the above arguments can be combined freely.

Start or stop monitoring in the background. Cannot be combined with any other
arguments. After enabling it you can view and filter the output by running
`capdump` as shown above.
```
capdump --enable
capdump --disable
```


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

capdump itself uses `CAP_DAC_READ_SEARCH` and `CAP_DAC_AUDIT_WRITE`?
Alternatively, `CAP_DAC_OVERRIDE`.

To get correct comm names (process names) you can do `sudo sh` and run the commands. 
Otherwise, the desktop manager may take over the name.

Note that some functions will call `cap_capable` directly, instead of
going through the other functions. Add option to view this directly?

## To-do list
- Filter by comm name, cap, pid
- Check for possible out of range indexing in the code
- Stop handler to disable when process exits
- Summary mode - based on pid or comm
- Return value?


echo 'p:capdump_ns ns_capable cap=$arg2 comm=$comm' > /sys/kernel/debug/tracing/kprobe_events
echo 'p:capdump_inode capable_wrt_inode_uidgid cap=$arg3 comm=$comm' >> /sys/kernel/debug/tracing/kprobe_events

echo 1 > /sys/kernel/debug/tracing/events/kprobes/capdump_inode/enable
echo 1 > /sys/kernel/debug/tracing/events/kprobes/capdump_ns/enable

cat /sys/kernel/debug/tracing/trace

echo 0 > /sys/kernel/debug/tracing/events/kprobes/capdump_ns/enable
echo 0 > /sys/kernel/debug/tracing/events/kprobes/capdump_inode/enable

echo -:capdump_ns >> /sys/kernel/debug/tracing/kprobe_events
echo -:capdump_inode >> /sys/kernel/debug/tracing/kprobe_events

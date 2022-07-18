# Capdump - Linux Capabilities monitor

Monitor when processes check capabilities to find out what they need.



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


capdump itself uses `CAP_DAC_OVERRIDE`.

- Filter by comm name, cap, pid
- Check for possible out of range indexing
- Stop handler to disable when program exits
- summary mode



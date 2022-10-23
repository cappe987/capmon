<!---
SPDX-License-Identifier: GPL-2.0-only
SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>
-->

# capmon - Linux Capabilities monitor

Monitor when processes check
[capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) to
find out what they require. Start `capmon` and run your program without sudo to
see the capability it fails on.

> Note: I do not know much about how capabilities works or how it's used in the
> kernel. Capmon might show more than required. I do not yet know why the
> kernel does all the extra checks.

# Installation

```
git submodule update --init --recursive
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j8
sudo make install
```

## Build dependencies (unsure about the kernel dependencies)

```
sudo apt install clang llvm libelf1 libelf-dev zlib1g-dev
```
- `CONFIG_PERF_EVENTS=y`?
- Kernel >= 5.10? ([BPF CO-RE](
  https://patchwork.ozlabs.org/project/buildroot/patch/29d2a8c7-44cd-da42-5fed-f17ec0f8ccf2@synopsys.com/))

## Run dependencies

- `CONFIG_DEBUG_INFO_BTF=y`
- Linux kernel >= 5.8 (BPF ring buffer)


# Usage

Start monitoring capability checks.
```
capmon
```

Filter by process name. Supports POSIX-Extended Regular Expressions (tip: use
quotation marks to avoid the shell interpreting as globbing).
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

## Using without sudo

To use Capmon without sudo you must assign `CAP_DAC_OVERRIDE` and
`CAP_SYS_ADMIN` to yourself and to `capmon`. Check out [this post by
Troglobit](https://troglobit.com/2016/12/11/a-life-without-sudo/) on how to use
capabilities.

# To-do list

- Write tests (and possibly test framework)
- Filter out capmons own checks on startup (only present with `-a`)?
- Re-add daemon mode? Not sure if I want this.

# Issues

- If starting with sudo, it will not properly exit if sudo timeout is reached
  (i.e. when you need to enter your password again). `Interrupted system call`.
  But will still remove the probes. Why? (STILL AN ISSUE?)
- To get correct comm names (process names) you can do `sudo sh` and run the commands. 
  Otherwise, the desktop manager may take over the name. (STILL AN ISSUE?)
- Note that some kernel functions will call `cap_capable` directly, instead of
  going through the other functions. Or they use some other less-common path.



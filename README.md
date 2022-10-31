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
make
sudo make install
```
The Makefile is a wrapper around CMake that will fetch the submodules and
output any build artifacts into the `build/` directory. For contributing, check
out [CONTRIBUTING.md](doc/CONTRIBUTING.md).

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


# Example
Check what capabilities it requires to run the command `ip link set dev eth0
down`. Capmon will output what the different processes (main and subprocesses)
requests.
```
capmon ip link set dev eth0 down
```

See [Monitor mode documentation](doc/monitor.md) for usage of the legacy monitor mode.

## Using without sudo

To use Capmon without sudo you must assign `CAP_DAC_OVERRIDE` and
`CAP_SYS_ADMIN` to yourself and to `capmon`. Check out [this post by
Troglobit](https://troglobit.com/2016/12/11/a-life-without-sudo/) on how to use
capabilities.

# Issues

- To get correct comm names (process names) you can do `sudo sh` and run the commands. 
  Otherwise, the desktop manager may take over the name. (STILL AN ISSUE?)
- Note that some kernel functions will call `cap_capable` directly, instead of
  going through the other functions. Or they use some other less-common path.



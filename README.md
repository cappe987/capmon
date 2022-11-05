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
> kernel. Capmon might show more than required. Some capability checks are not
> necessarily required for a program to run. One such example is `CAP_SYS_NICE`,
> where a program want to increase its priority but it's often not a strict
> requirement for functioning. Some capabilities are also subsets of others.

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
It is recommended to give Capmon the capabilities it needs. Running it with
sudo will pass sudo rights to any child processes, preventing the return value
of the cap check to be correct. 

To use Capmon without sudo you must assign `CAP_DAC_OVERRIDE` and
`CAP_SYS_ADMIN` to yourself and to `capmon`. Check out [this post by
Troglobit](https://troglobit.com/2016/12/11/a-life-without-sudo/) on how to use
capabilities.

# Issues

- To get correct comm names (process names) you can do `sudo sh` and run the commands. 
  Otherwise, the desktop manager may take over the name. (STILL AN ISSUE?)
- Note that some kernel functions will call `cap_capable` directly, instead of
  going through the other functions. Or they use some other less-common path.



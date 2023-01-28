<!---
SPDX-License-Identifier: GPL-2.0-only
SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>
-->

# capmon - Linux Capabilities checker/monitor

Monitor when processes check
[capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) to
find out what they require. Run `capmon <YOUR COMMAND>` to track the
capabilities it requires. It's important to **not** run your command with sudo
since that bypasses certain checks. Let the command fail at the first missing
capability check and add that capability, then try again and see if if fails on
more. Rinse and repeat until command runs successfully.

# Table of Contents
- [Installation](#installation)
  - [Build dependencies](#build-dependencies)
  - [Run dependencies](#run-dependencies)
- [Usage](#usage)
  - [Using without sudo](#using-without-sudo)
- [Contributing](#contributing)
- [Issues](#issues)



<a name="installation"/>

# Installation

```
make
sudo make install
```
The Makefile is a wrapper around CMake that will fetch the submodules and
output any build artifacts into the `build/` directory.



<a name="build-dependencies"/>

## Build dependencies

These should be available on most modern Linux distributions.
```
sudo apt install cmake clang llvm libelf1 libelf-dev zlib1g-dev
```
- `CONFIG_PERF_EVENTS=y`?
- Kernel >= 5.10? ([BPF CO-RE](
  https://patchwork.ozlabs.org/project/buildroot/patch/29d2a8c7-44cd-da42-5fed-f17ec0f8ccf2@synopsys.com/))



<a name="run-dependencies"/>

## Run dependencies

- `CONFIG_DEBUG_INFO_BTF=y`
- Linux kernel >= 5.8 (BPF ring buffer)



<a name="usage"/>

# Usage
Check what capabilities it requires to run the command `ip link set dev eth0
down`. Capmon will output what the different processes (main and subprocesses)
requests.
```
capmon ip link set dev eth0 down
```

See [Monitor mode documentation](doc/monitor.md) for usage of the legacy monitor mode.



<a name="using-without-sudo"/>

## Using without sudo
It is recommended to give Capmon the capabilities it needs. Running it with
sudo will pass sudo rights to any child processes, preventing the return value
of the cap check to be correct.

To use Capmon without sudo you must assign `CAP_DAC_OVERRIDE` and
`CAP_SYS_ADMIN` to yourself and to `capmon`. Check out [this post by
Troglobit](https://troglobit.com/2016/12/11/a-life-without-sudo/) on how to use
capabilities.



<a name="contributing"/>

# Contributing

For more detailed explanation on building it and how it works see
[CONTRIBUTING.md](docs/CONTRIBUTING.md)



<a name="issues"/>

# Issues

- To get correct comm names (process names) you can do `sudo sh` and run the commands.
  Otherwise, the desktop manager may take over the name. (Not sure if it's
  still an issue with process tracking)
- Note that some kernel functions will call `cap_capable` directly, instead of
  going through the other functions. Or they use some other less-common path.
  Use the flag `-a` to track everything.



<!---
SPDX-License-Identifier: GPL-2.0-only
SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>
-->

# Capmon - a Linux Capabilities monitor

Capabilities allows you to run commands without sudo. But sometimes it's hard
to figure out what capabilities it needs. Capmon monitors when processes check
[capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) to
find out what they require. Run `capmon '<COMMAND>'` to track the capabilities
it accesses. It's important to **not** run your command with sudo since that
bypasses certain checks. Let the command fail at the first missing capability
check and add that capability, then try again and see if if fails on more.
Rinse and repeat until command runs successfully.

For an introduction to capabilities see [A simpler life without
sudo](https://casan.se/blog/linux/a-simpler-life-without-sudo/).

## Table of Contents
- [Usage](#usage)
  - [Using without sudo](#using-without-sudo)
  - [Legacy mode](#legacy-mode)
- [Installation](#installation)
  - [Build dependencies](#build-dependencies)
  - [Run dependencies](#run-dependencies)
- [Contributing](#contributing)


## Usage

To use Capmon do
```sh
capmon '<cmd>'
```

For example:
```sh
capmon 'ip link netns add test'
```

It is recommended to enclose the command in quotes to avoid the shell from doing
any funny business with globbing or other special features, and to avoid Capmon
from interpreting the command's argument as its own. Capmon will run the command
with `/bin/sh`.

The output of the above command will be
```sh
[ip]
- [PASS] CAP_DAC_OVERRIDE
- [PASS] CAP_NET_ADMIN
```
because the `ip` command required the capabilities `CAP_NET_ADMIN` and
`CAP_DAC_OVERRIDE` for this particular task. Another example, `ip link set dev
tap0 up` only requires `CAP_NET_ADMIN`.

If the user didn't have the capabilities it would instead report `[FAIL]` on one
of the capabilities. If it failed on the first of the two then it may not even
show the second since commands often bail out as soon as they fail to do
something.

If a command is still failing even though Capmon doesn't report anything there
is the flag `-a` or `--all`. This changes the place where it listens to another
location which covers many more checks, some of which are not always necessary
and are allowed to fail. This is not the default mode as to not confuse the
user with a bunch of capabilities that usually will not matter.

### Using without sudo
It is recommended to give Capmon the capabilities it needs. Running it with
sudo will pass sudo rights to any child processes, preventing the return value
of the cap check to be correct.

To use Capmon without sudo you must assign `CAP_DAC_OVERRIDE` and
`CAP_SYS_ADMIN` to yourself and to `capmon`. For a guide on how to set
capabilities see [A simpler life without
sudo](https://casan.se/blog/linux/a-simpler-life-without-sudo/).

### Legacy mode

See [Monitor mode documentation](doc/monitor.md) for usage of the legacy
monitor mode.



## Installation

```
make
sudo make install
```
The Makefile is a wrapper around CMake that will fetch the submodules and
output any build artifacts into the `build/` directory.

### Build dependencies

These should be available on most modern Linux distributions.
```
sudo apt install cmake clang llvm libelf1 libelf-dev zlib1g-dev
```
- `CONFIG_PERF_EVENTS=y`?
- Linux kernel >= 5.10? ([BPF CO-RE](
  https://patchwork.ozlabs.org/project/buildroot/patch/29d2a8c7-44cd-da42-5fed-f17ec0f8ccf2@synopsys.com/))

### Run dependencies

- `CONFIG_DEBUG_INFO_BTF=y`
- Linux kernel >= 5.8 (BPF ring buffer)



## Contributing

For more detailed explanation on building it and how it works see
[CONTRIBUTING.md](doc/CONTRIBUTING.md)


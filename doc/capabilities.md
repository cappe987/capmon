<!---
SPDX-License-Identifier: GPL-2.0-only
SPDX-FileCopyrightText: 2023 Casper Andersson <casper.casan@gmail.com>
-->

# Capabilities documentation
This is a collection of notes on certain capabilities that may aid in
understanding what your program actually needs.

`CAP_SYS_NICE` allows setting the `nice` value, i.e., process scheduling
priority. This isn't always a strict requirement. Many applications may want to
have higher priority, but many will also run fine anyways. Failing this check
may be completely fine.

`CAP_SYS_ADMIN` is a superset of `CAP_BPF`, `CAP_CHECKPOINT_RESTORE`, and
`CAP_PERFMON`. Avoid using this if you can (`capabilities(7)` calls it "the new root").
Unfortunately, Capmon appears to requires this.

`CAP_DAC_OVERRIDE` is a superset of `CAP_DAC_READ_SEARCH`, as former encompasses
any file read/write/execute permissions, while the latter only encompasses file
read/execute.

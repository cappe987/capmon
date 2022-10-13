# Notes for migration


Remember to check/fix all licenses before merging.

Depends on `CONFIG_DEBUG_INFO_BTF=y` and Linux kernel >= 5.8.

Depends on `CONFIG_PERF_EVENTS=y` for building? Kernel >= 5.10?
https://patchwork.ozlabs.org/project/buildroot/patch/29d2a8c7-44cd-da42-5fed-f17ec0f8ccf2@synopsys.com/

You will need clang, libelf and zlib to build it?
$ apt install clang libelf1 libelf-dev zlib1g-dev

Depends on `CONFIG_DEBUG_INFO_BTF=y` for running




# Contributing

Anyone interested is free to contribute. I'm happy to help out with what I can.
This is just a hobby project that I made when learning about capabilities
because I found it difficult to know what different programs required.

# Build instructions

Build instructions for development. The Makefile is just a wrapper to make it easier to use.
```
git submodule update --init --recursive
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j8
```

Replace `-j8` with however many cores your computer has. The first build takes
some time due to having to build bpftool and libbpf.

# How it works

There are two modes. Proccess tracking (primary mode) and monitor (legacy
mode). I originally made the monitor mode inspired by `tcpdump`. It works well
for its purpose, but it's not the easiest to use if you don't fully know what
your program does, since it monitors everything.

## Process tracking
Process tracking runs the provided command and tracks its process ID (PID), as
well as any subprocesses spawned by it. This allows filtering for only the
desired processes. But there are cases where this does not work. It currently
does not support orphan processes. When the initial command finishes it stops
the tracking. One such example is Firefox. This is possible for future work,
but this is one reason why I have left monitor mode in.

It is mostly an extension of monitor mode. It keeps track of which PIDs checks
what capabilities similar to how monitor mode does it. On top of that it keeps
track of all PIDs related to the process. After the program has exited it
matches up the the capability checks with the PIDs spawned by the process.

Interactive programs are supported. Capmon ignores SIGINT (Ctrl-c) and passes
it through to the running command. But this means you cannot directly stop
Capmon. You can still use Ctrl-z to put it in background and then kill it.

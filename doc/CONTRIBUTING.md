# Contributing

## Build instructions

Build instructions for development. The Makefile is just a wrapper to make it easier to use.
```
git submodule update --init --recursive
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make -j8
```

Replace `-j8` with however many cores your computer has.

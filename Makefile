# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

BUILDDIR=build
BINARY=capmon

.PHONY: all install clean

$(BUILDDIR)/$(BINARY):
	git submodule update --init --recursive
	mkdir -p build
	cd $(BUILDDIR) && cmake -DCMAKE_BUILD_TYPE=Release ..
	cd $(BUILDDIR) && make -j8

all: $(BUILDDIR)/$(BINARY)

install: all
	cd $(BUILDDIR) && make install

clean:
	rm -rf $(BUILDDIR)

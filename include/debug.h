// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#ifndef _CAPMON_DEBUG_H
#define _CAPMON_DEBUG_H


#define DEBUG false

#if DEBUG
#define DBG(str, ...) printf(str, ##__VA_ARGS__)
#else
#define DBG(str, ...)
#endif


#endif /* _CAPMON_DEBUG_H */

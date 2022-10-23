// SPDX-License-Identifier: GPL-2.0-only
// SPDX-FileCopyrightText: 2022 Casper Andersson <casper.casan@gmail.com>

#ifndef _CAPMON_BITS_H_
#define _CAPMON_BITS_H_

#include <stdbool.h>
#include <limits.h>
#include <linux/types.h>

#define DECLARE_BITMAP(name, bits) __u32 name[(bits/32) + 1]

static inline void set_bit(int bit, __u32 *bitmap)
{
	bitmap[bit/32] |= 1 << (bit % 32);
}

static inline void clear_bit(int bit, __u32 *bitmap)
{
	bitmap[bit/32] &= ~(1 << (bit % 32));
}

static inline bool test_bit(int bit, const __u32 *bitmap)
{
	return bitmap[bit/32] & 1 << (bit % 32);
}

static inline void union_bitmap(__u32 *dest, const __u32 *src, int nr_bits)
{
	/* Subtract 1 since 32s bit should count only for one u32 */
	for (int i = 0; i <= (nr_bits-1)/32; i++) {
		dest[i] |= src[i];
	}
}

static inline void zero_bitmap(__u32 *bitmap, int nr_bits)
{
	/* Subtract 1 since 32s bit should count only for one u32 */
	for (int i = 0; i <= (nr_bits-1)/32; i++) {
		bitmap[i] &= 0;
	}
}

#endif /* _CAPMON_BITS_H_ */

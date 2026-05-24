// SPDX-License-Identifier: GPL-2.0

#if defined(__x86_64__) || defined(__powerpc__)

/*
 * Include usdt.h with defined USDT_NOP macro to use single
 * nop instruction.
 */

#ifdef __x86_64__
#define USDT_NOP .byte 0x90
#endif

#include "usdt.h"

__attribute__((aligned(16)))
void usdt_1(void)
{
	USDT(optimized_attach, usdt_1);
}

#endif

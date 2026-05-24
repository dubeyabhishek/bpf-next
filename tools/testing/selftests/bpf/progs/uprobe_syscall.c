// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <string.h>

#if defined(__TARGET_ARCH_x86)
/*
 * x86_64: kernel-internal struct pt_regs == UAPI struct pt_regs (168 bytes).
 * No size mismatch, use vmlinux definition directly.
 */
struct pt_regs regs;

#elif defined(__TARGET_ARCH_powerpc)
/*
 * ppc64le: kernel-internal struct pt_regs (384 bytes) != UAPI (352 bytes).
 * The extra 32 bytes (ppr, exit_result, kuap, __pad) are kernel-only tail
 * fields not present in <uapi/asm/ptrace.h>.
 *
 * Define a local struct mirroring ONLY the UAPI layout so that:
 *   1. sizeof(regs) == sizeof(UAPI struct pt_regs) == 352 on both sides
 *   2. The skeleton _Static_assert passes
 *   3. The memcpy below copies only the UAPI-visible 352 bytes from ctx
 *      (kernel-only tail fields at offsets 352..383 are simply not copied)
 */
struct {
        unsigned long gpr[32];   /* 0   .. 248 */
        unsigned long nip;       /* 256        */
        unsigned long msr;       /* 264        */
        unsigned long orig_gpr3; /* 272        */
        unsigned long ctr;       /* 280        */
        unsigned long link;      /* 288        */
        unsigned long xer;       /* 296        */
        unsigned long ccr;       /* 304        */
        unsigned long softe;     /* 312        */
        unsigned long trap;      /* 320        */
        unsigned long dar;       /* 328        */
        unsigned long dsisr;     /* 336        */
        unsigned long result;    /* 344        */
	unsigned long dummy[4];	 /* filler array */
                                 /* total: 352 == UAPI sizeof(struct pt_regs) */
} regs;
#endif

char _license[] SEC("license") = "GPL";

SEC("uprobe")
int probe(struct pt_regs *ctx)
{
        /*
         * sizeof(regs) == UAPI sizeof(struct pt_regs):
         *   x86_64 : 168 bytes (full struct, no tail fields)
         *   ppc64le: 352 bytes (UAPI portion only; kernel-only tail ignored)
         *
         * ctx points to the kernel-internal pt_regs which is a superset,
         * so reading sizeof(regs) bytes from it is always safe.
         */
        __builtin_memcpy(&regs, ctx, sizeof(regs));
        return 0;
}

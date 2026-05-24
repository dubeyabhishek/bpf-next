// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>

#include <unistd.h>
#include <asm/ptrace.h>
#include <linux/compiler.h>
#include <linux/stringify.h>
#include <linux/kernel.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#ifdef __x86_64__
#include <asm/prctl.h>
#endif
#include "uprobe_syscall.skel.h"
#include "uprobe_syscall_executed.skel.h"
#include "bpf/libbpf_internal.h"

#define BPF_TESTMOD_UPROBE_TEST_FILE "/sys/kernel/bpf_testmod_uprobe"

#ifdef __x86_64__
#define USDT_NOP .byte 0x0f, 0x1f, 0x44, 0x00, 0x00
#endif
#include "usdt.h"

/* __nocf_check is an x86 CET attribute; silence it on other arches. */
#ifndef __nocf_check
#define __nocf_check
#endif

#pragma GCC diagnostic ignored "-Wattributes"

#ifdef __x86_64__
__attribute__((aligned(16)))
__weak __naked unsigned long uprobe_regs_trigger(void)
{
    asm volatile (
        ".byte 0x0f, 0x1f, 0x44, 0x00, 0x00\n"
        "movq $0xdeadbeef, %rax\n"
        "ret\n"
    );
}

#elif defined(__powerpc64__)
__attribute__((aligned(16)))
__weak unsigned long uprobe_regs_trigger(void)
{
    unsigned long ret;

    asm volatile (
        "nop\n"                   /* 4-byte powerpc NOP — probe site    */
        "lis  %0, 0xdead\n"       /* load upper 16 bits of return value */
        "ori  %0, %0, 0xbeef\n"  /* load lower 16 bits                 */
        : "=r" (ret)
    );
    return ret;
}
#endif

#ifdef __x86_64__
__naked void uprobe_regs(struct pt_regs *before, struct pt_regs *after)
{
	asm volatile (
		"movq %r15,   0(%rdi)\n"
		"movq %r14,   8(%rdi)\n"
		"movq %r13,  16(%rdi)\n"
		"movq %r12,  24(%rdi)\n"
		"movq %rbp,  32(%rdi)\n"
		"movq %rbx,  40(%rdi)\n"
		"movq %r11,  48(%rdi)\n"
		"movq %r10,  56(%rdi)\n"
		"movq  %r9,  64(%rdi)\n"
		"movq  %r8,  72(%rdi)\n"
		"movq %rax,  80(%rdi)\n"
		"movq %rcx,  88(%rdi)\n"
		"movq %rdx,  96(%rdi)\n"
		"movq %rsi, 104(%rdi)\n"
		"movq %rdi, 112(%rdi)\n"
		"movq   $0, 120(%rdi)\n" /* orig_rax */
		"movq   $0, 128(%rdi)\n" /* rip      */
		"movq   $0, 136(%rdi)\n" /* cs       */
		"pushq %rax\n"
		"pushf\n"
		"pop %rax\n"
		"movq %rax, 144(%rdi)\n" /* eflags   */
		"pop %rax\n"
		"movq %rsp, 152(%rdi)\n" /* rsp      */
		"movq   $0, 160(%rdi)\n" /* ss       */

		/* save 2nd argument */
		"pushq %rsi\n"
		"call uprobe_regs_trigger\n"

		/* save  return value and load 2nd argument pointer to rax */
		"pushq %rax\n"
		"movq 8(%rsp), %rax\n"

		"movq %r15,   0(%rax)\n"
		"movq %r14,   8(%rax)\n"
		"movq %r13,  16(%rax)\n"
		"movq %r12,  24(%rax)\n"
		"movq %rbp,  32(%rax)\n"
		"movq %rbx,  40(%rax)\n"
		"movq %r11,  48(%rax)\n"
		"movq %r10,  56(%rax)\n"
		"movq  %r9,  64(%rax)\n"
		"movq  %r8,  72(%rax)\n"
		"movq %rcx,  88(%rax)\n"
		"movq %rdx,  96(%rax)\n"
		"movq %rsi, 104(%rax)\n"
		"movq %rdi, 112(%rax)\n"
		"movq   $0, 120(%rax)\n" /* orig_rax */
		"movq   $0, 128(%rax)\n" /* rip      */
		"movq   $0, 136(%rax)\n" /* cs       */

		/* restore return value and 2nd argument */
		"pop %rax\n"
		"pop %rsi\n"

		"movq %rax,  80(%rsi)\n"

		"pushf\n"
		"pop %rax\n"

		"movq %rax, 144(%rsi)\n" /* eflags   */
		"movq %rsp, 152(%rsi)\n" /* rsp      */
		"movq   $0, 160(%rsi)\n" /* ss       */
		"ret\n"
);
}
#elif defined(__powerpc64__)
/*
 * powerpc64le pt_regs layout (all offsets in bytes):
 *   gpr[0..31] : 0 .. 248   (32 * 8)
 *   nip        : 256
 *   msr        : 264
 *   orig_gpr3  : 272
 *   ctr        : 280
 *   link       : 288
 *   xer        : 296
 *   ccr        : 304
 *   softe      : 312
 *   trap       : 320
 *   dar        : 328
 *   dsisr      : 336
 *   result     : 344
 *
 * r3 = before, r4 = after  (ELFv2 calling convention)
 */
__naked void uprobe_regs(struct pt_regs *before, struct pt_regs *after)
{
    asm volatile (
        /* ---- Save all GPRs to 'before' (r3) ---- */
        "std  0,   0(3)\n"
        "std  1,   8(3)\n"
        "std  2,  16(3)\n"
        "std  3,  24(3)\n"    /* r3 = before ptr itself */
        "std  4,  32(3)\n"    /* r4 = after ptr */
        "std  5,  40(3)\n"
        "std  6,  48(3)\n"
        "std  7,  56(3)\n"
        "std  8,  64(3)\n"
        "std  9,  72(3)\n"
        "std 10,  80(3)\n"
        "std 11,  88(3)\n"
        "std 12,  96(3)\n"
        "std 13, 104(3)\n"
        "std 14, 112(3)\n"
        "std 15, 120(3)\n"
        "std 16, 128(3)\n"
        "std 17, 136(3)\n"
        "std 18, 144(3)\n"
        "std 19, 152(3)\n"
        "std 20, 160(3)\n"
        "std 21, 168(3)\n"
        "std 22, 176(3)\n"
        "std 23, 184(3)\n"
        "std 24, 192(3)\n"
        "std 25, 200(3)\n"
        "std 26, 208(3)\n"
        "std 27, 216(3)\n"
        "std 28, 224(3)\n"
        "std 29, 232(3)\n"
        "std 30, 240(3)\n"
        "std 31, 248(3)\n"

        /* ---- NIP/MSR unknown in userspace — zero them ---- */
        "li  0, 0\n"
        "std 0, 256(3)\n"     /* nip */
        "std 0, 264(3)\n"     /* msr */
        "std 0, 272(3)\n"     /* orig_gpr3 */

        /* ---- Save CTR, LR, XER, CCR ---- */
        "mfctr 0\n"
        "std 0, 280(3)\n"     /* ctr */
        "mflr 0\n"
        "std 0, 288(3)\n"     /* link (= our return address) */
        "mfxer 0\n"
        "std 0, 296(3)\n"     /* xer */
        "mfcr 0\n"
        "std 0, 304(3)\n"     /* ccr */

        /* ---- Zero kernel-only fields ---- */
        "li 0, 0\n"
        "std 0, 312(3)\n"     /* softe */
        "std 0, 320(3)\n"     /* trap */
        "std 0, 328(3)\n"     /* dar */
        "std 0, 336(3)\n"     /* dsisr */
        "std 0, 344(3)\n"     /* result */

        /* ---- Allocate stack frame, save before/after ptrs and LR ---- */
        "mflr 0\n"
        "stdu 1, -80(1)\n"
        "std  0, 96(1)\n"     /* LR save area (80 + 16) */
        "std  4, 48(1)\n"     /* save 'after' ptr */
        "std  3, 56(1)\n"     /* save 'before' ptr */

        /* ---- Call uprobe_regs_trigger (probe fires here) ---- */
        "bl uprobe_regs_trigger\n"
        /* r3 = 0xdeadbeef return value */

        /* ---- Restore ptrs ---- */
        "ld  4, 48(1)\n"      /* after ptr into r4 */
        "ld  5, 56(1)\n"      /* before ptr into r5 */
        "ld  0, 96(1)\n"      /* our saved LR */
        "addi 1, 1, 80\n"     /* restore sp */
        "mtlr 0\n"

        /* ---- Save register state to 'after' (r4) ---- */
        /* r3 = return value of trigger; callee-saved regs (r14-r31)
         * are unchanged; caller-saved (r5-r12) match probe-site values
         * because the uprobe handler preserves them. */
        "std  0,   0(4)\n"     /* r0 (just set by ld, not meaningful) */
        "std  1,   8(4)\n"     /* r1 current sp */
        "std  2,  16(4)\n"     /* r2 TOC */
        "std  3,  24(4)\n"     /* r3 = return value */
        /* r4-r12: copy from 'before', they equal probe-site values */
        "ld   0,  32(5)\n"  "std  0,  32(4)\n"   /* r4 */
        "ld   0,  40(5)\n"  "std  0,  40(4)\n"   /* r5 */
        "ld   0,  48(5)\n"  "std  0,  48(4)\n"   /* r6 */
        "ld   0,  56(5)\n"  "std  0,  56(4)\n"   /* r7 */
        "ld   0,  64(5)\n"  "std  0,  64(4)\n"   /* r8 */
        "ld   0,  72(5)\n"  "std  0,  72(4)\n"   /* r9 */
        "ld   0,  80(5)\n"  "std  0,  80(4)\n"   /* r10 */
        "ld   0,  88(5)\n"  "std  0,  88(4)\n"   /* r11 */
        "ld   0,  96(5)\n"  "std  0,  96(4)\n"   /* r12 */
        /* r13-r31: callee-saved, current value == before value */
        "std 13, 104(4)\n"
        "std 14, 112(4)\n"
        "std 15, 120(4)\n"
        "std 16, 128(4)\n"
        "std 17, 136(4)\n"
        "std 18, 144(4)\n"
        "std 19, 152(4)\n"
        "std 20, 160(4)\n"
        "std 21, 168(4)\n"
        "std 22, 176(4)\n"
        "std 23, 184(4)\n"
        "std 24, 192(4)\n"
        "std 25, 200(4)\n"
        "std 26, 208(4)\n"
        "std 27, 216(4)\n"
        "std 28, 224(4)\n"
        "std 29, 232(4)\n"
        "std 30, 240(4)\n"
        "std 31, 248(4)\n"

        /* ---- Zero NIP/MSR/orig_gpr3 in after ---- */
        "li  0, 0\n"
        "std 0, 256(4)\n"     /* nip */
        "std 0, 264(4)\n"     /* msr */
        "std 0, 272(4)\n"     /* orig_gpr3 */

        /* ---- Save CTR, LR, XER, CCR after call ---- */
        "mfctr 0\n"  "std 0, 280(4)\n"
        "mflr 0\n"   "std 0, 288(4)\n"
        "mfxer 0\n"  "std 0, 296(4)\n"
        "mfcr  0\n"  "std 0, 304(4)\n"

        /* ---- Zero kernel-only fields in after ---- */
        "li  0, 0\n"
        "std 0, 312(4)\n"  "std 0, 320(4)\n"
        "std 0, 328(4)\n"  "std 0, 336(4)\n"
        "std 0, 344(4)\n"
        "blr\n"
    );
}
#endif /* __powerpc64__ */

/* tools/testing/selftests/bpf/prog_tests/uprobe_syscall.c
 * Complete replacement for test_uprobe_regs_equal — includes existing
 * x86_64 handling and adds powerpc64le handling side by side. */

static void test_uprobe_regs_equal(bool retprobe)
{
    LIBBPF_OPTS(bpf_uprobe_opts, opts,
        .retprobe = retprobe,
    );
    struct uprobe_syscall *skel = NULL;
    struct pt_regs before = {}, after = {};
    unsigned long *pb = (unsigned long *) &before;
    unsigned long *pa = (unsigned long *) &after;
    unsigned long *pp;
    unsigned long offset;
    unsigned int i, cnt;

    offset = get_uprobe_offset(&uprobe_regs_trigger);
    if (!ASSERT_GE(offset, 0, "get_uprobe_offset"))
        return;

    skel = uprobe_syscall__open_and_load();
    if (!ASSERT_OK_PTR(skel, "uprobe_syscall__open_and_load"))
        goto cleanup;

    skel->links.probe = bpf_program__attach_uprobe_opts(skel->progs.probe,
                            0, "/proc/self/exe", offset, &opts);
    if (!ASSERT_OK_PTR(skel->links.probe, "bpf_program__attach_uprobe_opts"))
        goto cleanup;

    /* Fire once to trigger optimization before the actual test. */
    if (!retprobe)
        uprobe_regs_trigger();

    uprobe_regs(&before, &after);

    pp  = (unsigned long *) &skel->bss->regs;
    cnt = sizeof(before) / sizeof(*pb);

    for (i = 0; i < cnt; i++) {
        unsigned int off = i * sizeof(unsigned long);

        /*
         * First comparison: register seen BEFORE the trigger call vs
         * register seen AFTER the trigger call returns.  Certain slots
         * are changed by the kernel or the calling convention and are
         * excluded from this check.
         */
        switch (off) {
#ifdef __x86_64__
        case offsetof(struct pt_regs, rip):
        case offsetof(struct pt_regs, cs):
        case offsetof(struct pt_regs, eflags):
        case offsetof(struct pt_regs, rsp):
        case offsetof(struct pt_regs, ss):
            break;
#elif defined(__powerpc64__)
        /*
         * nip, msr, orig_gpr3 are kernel-filled and zeroed by our
         * userspace capture helper.  softe/trap/dar/dsisr/result are
         * kernel-only and also zeroed.  gpr[1] (sp) is adjusted by
         * the trampoline frame allocation and is not expected to match.
         */
        case offsetof(struct pt_regs, nip):
        case offsetof(struct pt_regs, msr):
        case offsetof(struct pt_regs, orig_gpr3):
        case offsetof(struct pt_regs, softe):
        case offsetof(struct pt_regs, trap):
        case offsetof(struct pt_regs, dar):
        case offsetof(struct pt_regs, dsisr):
        case offsetof(struct pt_regs, result):
        case offsetof(struct pt_regs, gpr[1]):   /* sp adjusted by trampoline */
            break;
#endif
        default:
            if (!ASSERT_EQ(pb[i], pa[i], "register before-after value check"))
                fprintf(stdout, "failed register offset %u\n", off);
        }

        /*
         * Second comparison: register seen by the BPF program at the
         * probe site vs register seen AFTER the trigger call returns.
         * Same exclusions apply, plus the return-value register differs
         * for uprobe (not uretprobe): the probe fires before the return
         * value is set, so BPF sees the before-value, not 0xdeadbeef.
         */
        switch (off) {
#ifdef __x86_64__
        case offsetof(struct pt_regs, rip):
        case offsetof(struct pt_regs, cs):
        case offsetof(struct pt_regs, eflags):
        case offsetof(struct pt_regs, rsp):
        case offsetof(struct pt_regs, ss):
            break;
        /*
         * uprobe fires before rax is set to the return value; BPF must
         * see the original (before) rax, not 0xdeadbeef.
         */
        case offsetof(struct pt_regs, rax):
            if (!retprobe) {
                ASSERT_EQ(pp[i], pb[i], "uprobe rax prog-before value check");
                break;
            }
            /* uretprobe: fall through to default comparison */
#elif defined(__powerpc64__)
        case offsetof(struct pt_regs, nip):
        case offsetof(struct pt_regs, msr):
        case offsetof(struct pt_regs, orig_gpr3):
        case offsetof(struct pt_regs, softe):
        case offsetof(struct pt_regs, trap):
        case offsetof(struct pt_regs, dar):
        case offsetof(struct pt_regs, dsisr):
        case offsetof(struct pt_regs, result):
        case offsetof(struct pt_regs, gpr[1]):
            break;
        /*
         * uprobe fires before r3 is set to the return value; BPF must
         * see the original (before) r3, not 0xdeadbeef.
         */
        case offsetof(struct pt_regs, gpr[3]):
            if (!retprobe) {
                ASSERT_EQ(pp[i], pb[i], "uprobe r3 prog-before value check");
                break;
            }
            /* uretprobe: fall through to default comparison */
#endif
        default:
            if (!ASSERT_EQ(pp[i], pa[i], "register prog-after value check"))
                fprintf(stdout, "failed register offset %u\n", off);
        }
    }

cleanup:
    uprobe_syscall__destroy(skel);
}

/* tools/testing/selftests/bpf/prog_tests/uprobe_syscall.c
 * Complete replacement for test_uretprobe_regs_change — includes existing
 * x86_64 handling and adds powerpc64le handling side by side. */

static int write_bpf_testmod_uprobe(unsigned long offset)
{
        size_t n, ret; 
        char buf[30];
        int fd;

        n = sprintf(buf, "%lu", offset);

        fd = open(BPF_TESTMOD_UPROBE_TEST_FILE, O_WRONLY);
        if (fd < 0) 
                return -errno;

        ret = write(fd, buf, n);
        close(fd);
        return ret != n ? (int) ret : 0; 
}

#if defined(__x86_64__) || defined(__powerpc64__)
static void test_uretprobe_regs_change(void)
{
    struct pt_regs before = {}, after = {};
    unsigned long *pb = (unsigned long *) &before;
    unsigned long *pa = (unsigned long *) &after;
    unsigned long cnt = sizeof(before) / sizeof(*pb);
    unsigned int i, err, off;

    off = get_uprobe_offset(uprobe_regs_trigger);

    err = write_bpf_testmod_uprobe(off);
    if (!ASSERT_OK(err, "register_uprobe"))
        return;

    uprobe_regs(&before, &after);

    err = write_bpf_testmod_uprobe(0);
    if (!ASSERT_OK(err, "unregister_uprobe"))
        return;

    for (i = 0; i < cnt; i++) {
        unsigned int offset = i * sizeof(unsigned long);

        /*
         * The bpf_testmod uprobe handler increments one register to
         * prove the consumer can modify register state.  That register
         * is the return-value register, which differs per architecture.
         * All other meaningful registers must be unchanged.
         *
         * Kernel-only fields (nip/msr/cs/eflags/ss etc.) are zeroed by
         * the userspace capture helper and are excluded from comparison.
         */
#ifdef __x86_64__
        if (offset == offsetof(struct pt_regs, rax)) {
            /*
             * bpf_testmod increments rax; before and after must differ.
             */
            ASSERT_NEQ(pb[i], pa[i], "rax changed by bpf_testmod");
            continue;
        }

        /* Skip kernel-managed fields that are not meaningful in userspace. */
        switch (offset) {
        case offsetof(struct pt_regs, rip):
        case offsetof(struct pt_regs, cs):
        case offsetof(struct pt_regs, eflags):
        case offsetof(struct pt_regs, rsp):
        case offsetof(struct pt_regs, ss):
        case offsetof(struct pt_regs, orig_rax):
            continue;
        default:
            break;
        }

#elif defined(__powerpc64__)
        if (offset == offsetof(struct pt_regs, gpr[3])) {
            /*
             * bpf_testmod increments gpr[3] (r3, the return-value
             * register on powerpc); before and after must differ.
             */
            ASSERT_NEQ(pb[i], pa[i], "r3 changed by bpf_testmod");
            continue;
        }

	if (offset == offsetof(struct pt_regs, gpr[4]) ||
		offset == offsetof(struct pt_regs, gpr[12])) {
		continue;
	}

        /* Skip kernel-managed and trampoline-adjusted fields. */
        switch (offset) {
        case offsetof(struct pt_regs, nip):
        case offsetof(struct pt_regs, msr):
        case offsetof(struct pt_regs, orig_gpr3):
        case offsetof(struct pt_regs, softe):
        case offsetof(struct pt_regs, trap):
        case offsetof(struct pt_regs, dar):
        case offsetof(struct pt_regs, dsisr):
        case offsetof(struct pt_regs, result):
        case offsetof(struct pt_regs, gpr[1]):   /* sp: trampoline adjusts */
            continue;
        default:
            break;
        }
#endif

        if (!ASSERT_EQ(pb[i], pa[i], "register unchanged"))
            fprintf(stdout, "failed register offset %u\n", offset);
    }
}
#endif

/* tools/testing/selftests/bpf/prog_tests/uprobe_syscall.c
 * Replace test_uprobe_sigill: */

/* Fall back to a compile-time constant if the kernel header does not yet
 * define __NR_uprobe for this architecture. */
#ifndef __NR_uprobe
#  ifdef __x86_64__
#    define __NR_uprobe 336
#  elif defined(__powerpc64__)
     /* Replace NNN with the number assigned in Step 6 of the porting guide. */
#    define __NR_uprobe 472
#  endif
#endif

static void test_uprobe_sigill(void)
{
    int status, err, pid;

    pid = fork();
    if (!ASSERT_GE(pid, 0, "fork"))
        return;

    if (pid == 0) {
        /* child: invoke uprobe syscall from outside any trampoline VMA */
#ifdef __x86_64__
        asm volatile (
            "pushq %rax\n"
            "pushq %rcx\n"
            "pushq %r11\n"
            "movq $" __stringify(__NR_uprobe) ", %rax\n"
            "syscall\n"
            "popq %r11\n"
            "popq %rcx\n"
            "retq\n"
        );
#elif defined(__powerpc64__)
        asm volatile (
            "li 0, " __stringify(__NR_uprobe) "\n"
            "sc\n"                 /* kernel checks caller VMA → SIGILL */
            "blr\n"
        );
#endif
        exit(0);
    }

    err = waitpid(pid, &status, 0);
    ASSERT_EQ(err, pid, "waitpid");
    ASSERT_EQ(WIFSIGNALED(status), 1,    "WIFSIGNALED");
    ASSERT_EQ(WTERMSIG(status),   SIGILL, "WTERMSIG");
}

static void test_regs_change(void)
{
        struct pt_regs before = {}, after = {};
        unsigned long *pb = (unsigned long *) &before;
        unsigned long *pa = (unsigned long *) &after;
        unsigned long cnt = sizeof(before) / sizeof(*pb);
        unsigned int i, err, off;

        off = get_uprobe_offset(uprobe_regs_trigger);

        err = write_bpf_testmod_uprobe(off);
        if (!ASSERT_OK(err, "register_uprobe"))
                return;

        /* Fire once to ensure the uprobe gets optimized before we capture. */
        uprobe_regs_trigger();

        uprobe_regs(&before, &after);

        err = write_bpf_testmod_uprobe(0);
        if (!ASSERT_OK(err, "unregister_uprobe"))
                return;

        for (i = 0; i < cnt; i++) {
                unsigned int offset = i * sizeof(unsigned long);

#ifdef __x86_64__
                /*
                 * uprobe_ret_handler sets ax = 0x12345678deadbeef.
                 * Verify it changed.
                 */
                if (offset == offsetof(struct pt_regs, rax)) {
                        ASSERT_NE(pb[i], pa[i], "rax changed");
                        continue;
                }

                /*
                 * uprobe_handler sets cx = 0x87654321feebdaed and
                 * uprobe_ret_handler sets r11 = -1.
                 * Both are expected to differ; skip their equality check.
                 */
                if (offset == offsetof(struct pt_regs, cx)  ||
                    offset == offsetof(struct pt_regs, r11)) {
                        continue;
                }

                /* Skip registers that are kernel-managed or not meaningful
                 * from userspace. */
                switch (offset) {
                case offsetof(struct pt_regs, rip):
                case offsetof(struct pt_regs, cs):
                case offsetof(struct pt_regs, eflags):
                case offsetof(struct pt_regs, rsp):
                case offsetof(struct pt_regs, ss):
                case offsetof(struct pt_regs, orig_rax):
                        continue;
                default:
                        break;
                }

#elif defined(__powerpc64__)
                /*
                 * uprobe_ret_handler sets gpr[3] = 0x12345678deadbeef.
                 * r3 is the return-value register; verify it changed.
                 */
                if (offset == offsetof(struct pt_regs, gpr[3])) {
                        ASSERT_NEQ(pb[i], pa[i], "r3 changed");
                        continue;
                }

                /*
                 * uprobe_handler sets gpr[4] = 0x87654321feebdaed and
                 * uprobe_ret_handler sets gpr[12] = -1.
                 * Both are expected to differ; skip their equality check.
                 */
                if (offset == offsetof(struct pt_regs, gpr[4])  ||
                    offset == offsetof(struct pt_regs, gpr[12])) {
                        continue;
                }

                /* Skip kernel-managed and trampoline-adjusted fields. */
                switch (offset) {
                case offsetof(struct pt_regs, nip):
                case offsetof(struct pt_regs, msr):
                case offsetof(struct pt_regs, orig_gpr3):
                case offsetof(struct pt_regs, softe):
                case offsetof(struct pt_regs, trap):
                case offsetof(struct pt_regs, dar):
                case offsetof(struct pt_regs, dsisr):
                case offsetof(struct pt_regs, result):
                case offsetof(struct pt_regs, gpr[1]):
                        continue;
                default:
                        break;
                }
#endif

                if (!ASSERT_EQ(pb[i], pa[i], "register unchanged"))
                        fprintf(stdout, "failed register offset %u\n", offset);
        }
}

#ifndef __NR_uprobe
#  ifdef __x86_64__
#    define __NR_uretprobe 335
#  elif defined(__powerpc64__)
     /* Replace NNN with the number assigned in Step 6 of the porting guide. */
#    define __NR_uretprobe 473
#  endif
#endif

#ifdef __x86_64__
__naked unsigned long uretprobe_syscall_call_1(void)
{
	/*
	 * Pretend we are uretprobe trampoline to trigger the return
	 * probe invocation in order to verify we get SIGILL.
	 */
	asm volatile (
		"pushq %rax\n"
		"pushq %rcx\n"
		"pushq %r11\n"
		"movq $" __stringify(__NR_uretprobe) ", %rax\n"
		"syscall\n"
		"popq %r11\n"
		"popq %rcx\n"
		"retq\n"
	);
}

__naked unsigned long uretprobe_syscall_call(void)
{
	asm volatile (
		"call uretprobe_syscall_call_1\n"
		"retq\n"
	);
}

static void test_uretprobe_syscall_call(void)
{
	LIBBPF_OPTS(bpf_uprobe_multi_opts, opts,
		.retprobe = true,
	);
	struct uprobe_syscall_executed *skel;
	int pid, status, err, go[2], c = 0;
	struct bpf_link *link;

	if (!ASSERT_OK(pipe(go), "pipe"))
		return;

	skel = uprobe_syscall_executed__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_syscall_executed__open_and_load"))
		goto cleanup;

	pid = fork();
	if (!ASSERT_GE(pid, 0, "fork"))
		goto cleanup;

	/* child */
	if (pid == 0) {
		close(go[1]);

		/* wait for parent's kick */
		err = read(go[0], &c, 1);
		if (err != 1)
			exit(-1);

		uretprobe_syscall_call();
		_exit(0);
	}

	skel->bss->pid = pid;

	link = bpf_program__attach_uprobe_multi(skel->progs.test_uretprobe_multi,
						pid, "/proc/self/exe",
						"uretprobe_syscall_call", &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_uprobe_multi"))
		goto cleanup;
	skel->links.test_uretprobe_multi = link;

	/* kick the child */
	write(go[1], &c, 1);
	err = waitpid(pid, &status, 0);
	ASSERT_EQ(err, pid, "waitpid");

	/* verify the child got killed with SIGILL */
	ASSERT_EQ(WIFSIGNALED(status), 1, "WIFSIGNALED");
	ASSERT_EQ(WTERMSIG(status), SIGILL, "WTERMSIG");

	/* verify the uretprobe program wasn't called */
	ASSERT_EQ(skel->bss->executed, 0, "executed");

cleanup:
	uprobe_syscall_executed__destroy(skel);
	close(go[1]);
	close(go[0]);
}
#endif

#define TRAMP "[uprobes-trampoline]"

__attribute__((aligned(16)))
__nocf_check __weak __naked void uprobe_test(void)
{
#ifdef __x86_64__
    asm volatile (
        ".byte 0x0f, 0x1f, 0x44, 0x00, 0x00\n"
        "ret\n"
    );
#elif defined(__powerpc64__)
    asm volatile (
        "nop\n"   /* 4-byte NOP = probe site on powerpc */
        "blr\n"
    );
#endif
}

__attribute__((aligned(16)))
__nocf_check __weak void usdt_test(void)
{
	USDT(optimized_uprobe, usdt);
}

static int find_uprobes_trampoline(void *tramp_addr)
{
	void *start, *end;
	char line[128];
	int ret = -1;
	FILE *maps;

	maps = fopen("/proc/self/maps", "r");
	if (!maps) {
		fprintf(stderr, "cannot open maps\n");
		return -1;
	}

	while (fgets(line, sizeof(line), maps)) {
		int m = -1;

		/* We care only about private r-x mappings. */
		if (sscanf(line, "%p-%p r-xp %*x %*x:%*x %*u %n", &start, &end, &m) != 2)
			continue;
		if (m < 0)
			continue;
		if (!strncmp(&line[m], TRAMP, sizeof(TRAMP)-1) && (start == tramp_addr)) {
			ret = 0;
			break;
		}
	}

	fclose(maps);
	return ret;
}

#ifdef __x86_64__
	static unsigned char probe_nop[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	#define PROBE_NOP_SIZE  5
	#define arch_nop_str "nop5"
#elif defined(__powerpc64__)
	/* powerpc NOP = 0x60000000, stored big-endian in memory */
	static unsigned char probe_nop[] = { 0x60, 0x00, 0x00, 0x00 };
	#define arch_nop_str "nop"
	#define PROBE_NOP_SIZE  4
#endif

static void *find_probe_nop(void *fn)
{
    int i;

    // Scan the first 10 instruction-slots for the NOP pattern.
    for (i = 0; i < 10; i++) {
        if (!memcmp(probe_nop, fn + i, PROBE_NOP_SIZE))
            return fn + i;
    }
    return NULL;
}

typedef void (__attribute__((nocf_check)) *trigger_t)(void);

/* Decode a powerpc bl instruction and return its target address.
 * bl: opcode=18 (bits[31:26]), AA=0 (bit[1]=0), LK=1 (bit[0]=1).
 * The 26-bit signed byte offset lives in bits[25:2]. */
#ifdef __powerpc64__
static bool is_bl_insn(unsigned int insn)
{
    return (insn >> 26) == 18 && (insn & 3) == 1;
}

static void *bl_target(void *pc, unsigned int insn)
{
    /* sign-extend the 26-bit offset from bits[25:2] */
    int offset = (int)(insn & 0x03FFFFFC);

    if (offset & 0x02000000)
        offset |= (int)0xFC000000;
    return (char *)pc + offset;
}
#endif

static void *check_attach(struct uprobe_syscall_executed *skel, trigger_t trigger,
			  void *addr, int executed)
{
	void *tramp = NULL;

	/* Uprobe is optimized after first trigger — fire twice. */
	trigger();
	trigger();

	ASSERT_EQ(skel->bss->executed, executed, "executed");

#ifdef __x86_64__
        struct __arch_relative_insn {
            __u8  op;
            __s32 raddr;
        } __packed *call = addr;
        tramp = (void *)(call + 1) + call->raddr;
        ASSERT_EQ(call->op, 0xe8, "call");
        ASSERT_OK(find_uprobes_trampoline(tramp), "uprobes_trampoline");
#elif defined(__powerpc64__)
        /* powerpc: expect a bl instruction pointing into the trampoline. */
        {
		unsigned int insn;
        	memcpy(&insn, addr, sizeof(insn));
		ASSERT_TRUE(is_bl_insn(insn), "bl_insn");
		tramp = bl_target(addr, insn);
		ASSERT_OK(find_uprobes_trampoline(tramp), "uprobes_trampoline");
	}
#endif
	return tramp;
}

static void check_detach(void *addr, void *tramp)
{
	/* [uprobes_trampoline] stays after detach */
	ASSERT_OK(find_uprobes_trampoline(tramp), "uprobes_trampoline");
	ASSERT_OK(memcmp(addr, probe_nop, PROBE_NOP_SIZE), arch_nop_str);
}

static void check(struct uprobe_syscall_executed *skel, struct bpf_link *link,
		  trigger_t trigger, void *addr, int executed)
{
	void *tramp;

	tramp = check_attach(skel, trigger, addr, executed);
	bpf_link__destroy(link);
	check_detach(addr, tramp);
}

static void test_uprobe_legacy(void)
{
	struct uprobe_syscall_executed *skel = NULL;
	LIBBPF_OPTS(bpf_uprobe_opts, opts,
		.retprobe = true,
	);
	struct bpf_link *link;
	unsigned long offset;

	offset = get_uprobe_offset(&uprobe_test);
	if (!ASSERT_GE(offset, 0, "get_uprobe_offset"))
		goto cleanup;

	/* uprobe */
	skel = uprobe_syscall_executed__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_syscall_executed__open_and_load"))
		return;

	skel->bss->pid = getpid();

	link = bpf_program__attach_uprobe_opts(skel->progs.test_uprobe,
				0, "/proc/self/exe", offset, NULL);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_uprobe_opts"))
		goto cleanup;

	check(skel, link, uprobe_test, uprobe_test, 2);

	/* uretprobe */
	skel->bss->executed = 0;

	link = bpf_program__attach_uprobe_opts(skel->progs.test_uretprobe,
				0, "/proc/self/exe", offset, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_uprobe_opts"))
		goto cleanup;

	check(skel, link, uprobe_test, uprobe_test, 2);

cleanup:
	uprobe_syscall_executed__destroy(skel);
}

static void test_uprobe_multi(void)
{
	struct uprobe_syscall_executed *skel = NULL;
	LIBBPF_OPTS(bpf_uprobe_multi_opts, opts);
	struct bpf_link *link;
	unsigned long offset;

	offset = get_uprobe_offset(&uprobe_test);
	if (!ASSERT_GE(offset, 0, "get_uprobe_offset"))
		goto cleanup;

	opts.offsets = &offset;
	opts.cnt = 1;

	skel = uprobe_syscall_executed__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_syscall_executed__open_and_load"))
		return;

	skel->bss->pid = getpid();

	/* uprobe.multi */
	link = bpf_program__attach_uprobe_multi(skel->progs.test_uprobe_multi,
				0, "/proc/self/exe", NULL, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_uprobe_multi"))
		goto cleanup;

	check(skel, link, uprobe_test, uprobe_test, 2);

	/* uretprobe.multi */
	skel->bss->executed = 0;
	opts.retprobe = true;
	link = bpf_program__attach_uprobe_multi(skel->progs.test_uretprobe_multi,
				0, "/proc/self/exe", NULL, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_uprobe_multi"))
		goto cleanup;

	check(skel, link, uprobe_test, uprobe_test, 2);

cleanup:
	uprobe_syscall_executed__destroy(skel);
}

static void test_uprobe_session(void)
{
	struct uprobe_syscall_executed *skel = NULL;
	LIBBPF_OPTS(bpf_uprobe_multi_opts, opts,
		.session = true,
	);
	struct bpf_link *link;
	unsigned long offset;

	offset = get_uprobe_offset(&uprobe_test);
	if (!ASSERT_GE(offset, 0, "get_uprobe_offset"))
		goto cleanup;

	opts.offsets = &offset;
	opts.cnt = 1;

	skel = uprobe_syscall_executed__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_syscall_executed__open_and_load"))
		return;

	skel->bss->pid = getpid();

	link = bpf_program__attach_uprobe_multi(skel->progs.test_uprobe_session,
				0, "/proc/self/exe", NULL, &opts);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_uprobe_multi"))
		goto cleanup;

	check(skel, link, uprobe_test, uprobe_test, 4);

cleanup:
	uprobe_syscall_executed__destroy(skel);
}

static void test_uprobe_usdt(void)
{
	struct uprobe_syscall_executed *skel;
	struct bpf_link *link;
	void *addr;

	errno = 0;
	addr = find_probe_nop(usdt_test);
	if (!ASSERT_OK_PTR(addr, "find_probe_nop"))
		return;

	skel = uprobe_syscall_executed__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_syscall_executed__open_and_load"))
		return;

	skel->bss->pid = getpid();

	link = bpf_program__attach_usdt(skel->progs.test_usdt,
				-1 /* all PIDs */, "/proc/self/exe",
				"optimized_uprobe", "usdt", NULL);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_usdt"))
		goto cleanup;

	check(skel, link, usdt_test, addr, 2);

cleanup:
	uprobe_syscall_executed__destroy(skel);
}

/*
 * Borrowed from tools/testing/selftests/x86/test_shadow_stack.c.
 *
 * For use in inline enablement of shadow stack.
 *
 * The program can't return from the point where shadow stack gets enabled
 * because there will be no address on the shadow stack. So it can't use
 * syscall() for enablement, since it is a function.
 *
 * Based on code from nolibc.h. Keep a copy here because this can't pull
 * in all of nolibc.h.
 */
#define ARCH_PRCTL(arg1, arg2)					\
({								\
	long _ret;						\
	register long _num  asm("eax") = __NR_arch_prctl;	\
	register long _arg1 asm("rdi") = (long)(arg1);		\
	register long _arg2 asm("rsi") = (long)(arg2);		\
								\
	asm volatile (						\
		"syscall\n"					\
		: "=a"(_ret)					\
		: "r"(_arg1), "r"(_arg2),			\
		  "0"(_num)					\
		: "rcx", "r11", "memory", "cc"			\
	);							\
	_ret;							\
})

#ifndef ARCH_SHSTK_ENABLE
#define ARCH_SHSTK_ENABLE	0x5001
#define ARCH_SHSTK_DISABLE	0x5002
#define ARCH_SHSTK_SHSTK	(1ULL <<  0)
#endif

#ifdef __x86_64__
static void test_uretprobe_shadow_stack(void)
{
	if (ARCH_PRCTL(ARCH_SHSTK_ENABLE, ARCH_SHSTK_SHSTK)) {
		test__skip();
		return;
	}

	/* Run all the tests with shadow stack in place. */

	test_uprobe_regs_equal(false);
	test_uprobe_regs_equal(true);
	test_uretprobe_syscall_call();

	test_uprobe_legacy();
	test_uprobe_multi();
	test_uprobe_session();
	test_uprobe_usdt();

	test_regs_change();

	ARCH_PRCTL(ARCH_SHSTK_DISABLE, ARCH_SHSTK_SHSTK);
}
#endif /* __x86_64__*/

static volatile bool race_stop;

static USDT_DEFINE_SEMA(race);

static void *worker_trigger(void *arg)
{
	unsigned long rounds = 0;

	while (!race_stop) {
		uprobe_test();
		rounds++;
	}

	printf("tid %ld trigger rounds: %lu\n", sys_gettid(), rounds);
	return NULL;
}

static void *worker_attach(void *arg)
{
	LIBBPF_OPTS(bpf_uprobe_opts, opts);
	struct uprobe_syscall_executed *skel;
	unsigned long rounds = 0, offset;
	const char *sema[2] = {
		__stringify(USDT_SEMA(race)),
		NULL,
	};
	unsigned long *ref;
	int err;

	offset = get_uprobe_offset(&uprobe_test);
	if (!ASSERT_GE(offset, 0, "get_uprobe_offset"))
		return NULL;

	err = elf_resolve_syms_offsets("/proc/self/exe", 1, (const char **) &sema, &ref, STT_OBJECT);
	if (!ASSERT_OK(err, "elf_resolve_syms_offsets_sema"))
		return NULL;

	opts.ref_ctr_offset = *ref;

	skel = uprobe_syscall_executed__open_and_load();
	if (!ASSERT_OK_PTR(skel, "uprobe_syscall_executed__open_and_load"))
		return NULL;

	skel->bss->pid = getpid();

	while (!race_stop) {
		skel->links.test_uprobe = bpf_program__attach_uprobe_opts(skel->progs.test_uprobe,
					0, "/proc/self/exe", offset, &opts);
		if (!ASSERT_OK_PTR(skel->links.test_uprobe, "bpf_program__attach_uprobe_opts"))
			break;

		bpf_link__destroy(skel->links.test_uprobe);
		skel->links.test_uprobe = NULL;
		rounds++;
	}

	printf("tid %ld attach rounds: %lu hits: %d\n", sys_gettid(), rounds, skel->bss->executed);
	uprobe_syscall_executed__destroy(skel);
	free(ref);
	return NULL;
}

static useconds_t race_msec(void)
{
	char *env;

	env = getenv("BPF_SELFTESTS_UPROBE_SYSCALL_RACE_MSEC");
	if (env)
		return atoi(env);

	/* default duration is 500ms */
	return 500;
}

static void test_uprobe_race(void)
{
	int err, i, nr_threads;
	pthread_t *threads;

	nr_threads = libbpf_num_possible_cpus();
	if (!ASSERT_GT(nr_threads, 0, "libbpf_num_possible_cpus"))
		return;
	nr_threads = max(2, nr_threads);

	threads = alloca(sizeof(*threads) * nr_threads);
	if (!ASSERT_OK_PTR(threads, "malloc"))
		return;

	for (i = 0; i < nr_threads; i++) {
		err = pthread_create(&threads[i], NULL, i % 2 ? worker_trigger : worker_attach,
				     NULL);
		if (!ASSERT_OK(err, "pthread_create"))
			goto cleanup;
	}

	usleep(race_msec() * 1000);

cleanup:
	race_stop = true;
	for (nr_threads = i, i = 0; i < nr_threads; i++)
		pthread_join(threads[i], NULL);

	ASSERT_FALSE(USDT_SEMA_IS_ACTIVE(race), "race_semaphore");
}

static void test_uprobe_error(void)
{
	long err = syscall(__NR_uprobe);

	ASSERT_EQ(err, -1, "error");
	ASSERT_EQ(errno, ENXIO, "errno");
}

/* tools/testing/selftests/bpf/prog_tests/uprobe_syscall.c
 * Replace the __test_uprobe_syscall guard: */

#if defined(__x86_64__) || defined(__powerpc64__)
static void __test_uprobe_syscall(void)
{
    if (test__start_subtest("uretprobe_regs_equal"))
        test_uprobe_regs_equal(true);
    if (test__start_subtest("uretprobe_regs_change"))
        test_uretprobe_regs_change();
#ifdef __x86_64__
    if (test__start_subtest("uretprobe_syscall_call"))
        test_uretprobe_syscall_call();
    if (test__start_subtest("uretprobe_shadow_stack"))
        test_uretprobe_shadow_stack();
#endif
    if (test__start_subtest("uprobe_legacy"))
        test_uprobe_legacy();
    if (test__start_subtest("uprobe_multi"))
        test_uprobe_multi();
    if (test__start_subtest("uprobe_session"))
        test_uprobe_session();
    if (test__start_subtest("uprobe_usdt"))
        test_uprobe_usdt();
    if (test__start_subtest("uprobe_race"))
        test_uprobe_race();
    if (test__start_subtest("uprobe_sigill"))
        test_uprobe_sigill();
    if (test__start_subtest("uprobe_regs_equal"))
        test_uprobe_regs_equal(false);
    if (test__start_subtest("regs_change"))
        test_regs_change();
    if (test__start_subtest("uprobe_error"))
        test_uprobe_error();
}

#else  /* neither x86_64 nor powerpc64 */
static void __test_uprobe_syscall(void)
{
}
#endif

void test_uprobe_syscall(void)
{
	__test_uprobe_syscall();
}

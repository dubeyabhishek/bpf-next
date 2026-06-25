// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * User-space Probes (UProbes) for powerpc
 *
 * Copyright IBM Corporation, 2007-2012
 *
 * Adapted from the x86 port by Ananth N Mavinakayanahalli <ananth@in.ibm.com>
 */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/uprobes.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/kdebug.h>

#include <asm/sstep.h>
#include <asm/inst.h>
#include <asm/ppc-opcode.h>

#define UPROBE_TRAP_NR	UINT_MAX

#ifdef CONFIG_PPC64

static int tramp_mremap(const struct vm_special_mapping *sm,
                        struct vm_area_struct *new_vma)
{
    return -EPERM;
}

static struct page *tramp_mapping_pages[2] __ro_after_init;

static struct vm_special_mapping tramp_mapping = {
    .name   = "[uprobes-trampoline]",
    .mremap = tramp_mremap,
    .pages  = tramp_mapping_pages,
};

struct uprobe_trampoline {
    struct hlist_node   node;
    unsigned long       vaddr;   /* user-space address of the mapped page */
};

/*
 * Trampoline stack frame (offsets from r1 after stdu r1,-128(r1)):
 *   0: back chain, 8: LR (=probe_addr+4), 16: CR, 24-96: r3-r12
 */
#define UPROBE_TRAMP_FRAME_SIZE    128
#define UPROBE_TRAMP_LR_OFFSET       8
#define UPROBE_TRAMP_CR_OFFSET      16
#define UPROBE_TRAMP_GPR3_OFFSET    24

static bool is_reachable_by_bl(unsigned long vtramp, unsigned long vaddr)
{
    long delta = (long)(vtramp - vaddr);

    /* bl: 26-bit signed byte offset, range -(1<<25) to +(1<<25)-4 */
    return delta >= -(1L << 25) && delta <= ((1L << 25) - 4) &&
           !(delta & 3);
}

static unsigned long find_nearest_trampoline(unsigned long vaddr)
{
    struct vm_unmapped_area_info info = {
        .length     = PAGE_SIZE,
        .align_mask = ~PAGE_MASK,
        .low_limit  = max(PAGE_SIZE,  vaddr - (1UL << 25)),
        .high_limit = min(TASK_SIZE,  vaddr + (1UL << 25)),
    };

    return vm_unmapped_area(&info);
}

static struct uprobe_trampoline *create_uprobe_trampoline(unsigned long vaddr)
{
    struct mm_struct *mm = current->mm;
    struct uprobe_trampoline *tramp;
    struct vm_area_struct *vma;

    vaddr = find_nearest_trampoline(vaddr);
    if (IS_ERR_VALUE(vaddr))
        return NULL;

    tramp = kzalloc(sizeof(*tramp), GFP_KERNEL);
    if (unlikely(!tramp))
        return NULL;

    tramp->vaddr = vaddr;
    vma = _install_special_mapping(mm, tramp->vaddr, PAGE_SIZE,
            VM_READ | VM_EXEC | VM_MAYEXEC | VM_MAYREAD |
            VM_DONTCOPY | VM_IO,
            &tramp_mapping);
    if (IS_ERR(vma)) {
        kfree(tramp);
        return NULL;
    }
    return tramp;
}

static struct uprobe_trampoline *get_uprobe_trampoline(unsigned long vaddr,
                                                        bool *new)
{
    struct uprobes_state *state = &current->mm->uprobes_state;
    struct uprobe_trampoline *tramp;

    if (vaddr > TASK_SIZE || vaddr < PAGE_SIZE)
        return NULL;

    hlist_for_each_entry(tramp, &state->head_tramps, node) {
        if (is_reachable_by_bl(tramp->vaddr, vaddr)) {
            *new = false;
            return tramp;
        }
    }

    tramp = create_uprobe_trampoline(vaddr);
    if (!tramp)
        return NULL;

    *new = true;
    hlist_add_head(&tramp->node, &state->head_tramps);
    return tramp;
}

static void destroy_uprobe_trampoline(struct uprobe_trampoline *tramp)
{
    /* VMA left mapped; all mappings share one .rodata page */
    hlist_del(&tramp->node);
    kfree(tramp);
}

void arch_uprobe_init_state(struct mm_struct *mm)
{
    INIT_HLIST_HEAD(&mm->uprobes_state.head_tramps);
}

void arch_uprobe_clear_state(struct mm_struct *mm)
{
    struct uprobes_state *state = &mm->uprobes_state;
    struct uprobe_trampoline *tramp;
    struct hlist_node *n;

    hlist_for_each_entry_safe(tramp, n, &state->head_tramps, node)
        destroy_uprobe_trampoline(tramp);
}

asm (
    ".pushsection .rodata\n"
    ".balign " __stringify(PAGE_SIZE) "\n"
    "uprobe_trampoline_entry:\n"
    /* Allocate frame; stdu writes old r1 to 0(new r1) as back chain */
    "stdu  1, -" __stringify(UPROBE_TRAMP_FRAME_SIZE) "(1)\n"
    /* Save LR (=probe_addr+4 written by bl at probe site) */
    "mflr  0\n"
    "std   0, " __stringify(UPROBE_TRAMP_LR_OFFSET) "(1)\n"
    /* Save CR; sc clobbers CR0 */
    "mfcr  0\n"
    "std   0, " __stringify(UPROBE_TRAMP_CR_OFFSET) "(1)\n"
    /* Save r3-r12; sc clobbers these; values equal probe-site originals
     * because std only reads registers */
    "std   3,  24(1)\n"
    "std   4,  32(1)\n"
    "std   5,  40(1)\n"
    "std   6,  48(1)\n"
    "std   7,  56(1)\n"
    "std   8,  64(1)\n"
    "std   9,  72(1)\n"
    "std  10,  80(1)\n"
    "std  11,  88(1)\n"
    "std  12,  96(1)\n"
    "li    0, " __stringify(__NR_uprobe) "\n"
    "sc\n"
    /* Restore r3-r12; handler may have updated them in the frame */
    "ld    3,  24(1)\n"
    "ld    4,  32(1)\n"
    "ld    5,  40(1)\n"
    "ld    6,  48(1)\n"
    "ld    7,  56(1)\n"
    "ld    8,  64(1)\n"
    "ld    9,  72(1)\n"
    "ld   10,  80(1)\n"
    "ld   11,  88(1)\n"
    "ld   12,  96(1)\n"
    "ld    0, " __stringify(UPROBE_TRAMP_CR_OFFSET) "(1)\n"
    "mtcr  0\n"
    "ld    0, " __stringify(UPROBE_TRAMP_LR_OFFSET) "(1)\n"
    "addi  1, 1, " __stringify(UPROBE_TRAMP_FRAME_SIZE) "\n"
    "mtlr  0\n"
    "blr\n"
    ".balign " __stringify(PAGE_SIZE) "\n"
    ".popsection\n"
);

extern u8 uprobe_trampoline_entry[];

static int __init arch_uprobes_init(void)
{
    tramp_mapping_pages[0] = virt_to_page(uprobe_trampoline_entry);
    return 0;
}
late_initcall(arch_uprobes_init);

static bool __in_uprobe_trampoline(unsigned long ip)
{
    struct vm_area_struct *vma = vma_lookup(current->mm, ip);

    return vma && vma_is_special_mapping(vma, &tramp_mapping);
}

static bool in_uprobe_trampoline(unsigned long ip)
{
    struct mm_struct *mm = current->mm;
    bool found;

    mmap_read_lock(mm);
    found = __in_uprobe_trampoline(ip);
    mmap_read_unlock(mm);
    return found;
}

SYSCALL_DEFINE0(uprobe)
{
    struct pt_regs *regs      = task_pt_regs(current);
    unsigned long   tramp_nip = regs->nip;
    unsigned long   tramp_r1  = regs->gpr[1];
    unsigned long   probe_addr;
    int err = 0, i;

    /* Reject calls from outside kernel-installed trampoline VMAs */
    if (!in_uprobe_trampoline(tramp_nip))
        goto sigill;

    /*
     * bl stored probe_addr+4 in LR; trampoline's mflr copied it to r0
     * leaving LR intact, so regs->link still holds probe_addr+4.
     */
    probe_addr = regs->link - 4;

    /* Present probe-site register view to consumers */
    regs->nip    = probe_addr;
    regs->gpr[1] = tramp_r1 + UPROBE_TRAMP_FRAME_SIZE;

    handle_syscall_uprobe(regs, probe_addr);

    /*
     * Write back consumer-modified gpr[3..12] into the trampoline frame;
     * the trampoline's ld instructions restore them to user registers.
     */
    for (i = 0; i < 10; i++) {
        err |= put_user(regs->gpr[3 + i],
                        (unsigned long __user *)
                        (tramp_r1 + UPROBE_TRAMP_GPR3_OFFSET + i * 8));
    }
    if (err)
        goto sigill;

    /* Restore trampoline context so sc return lands back in trampoline */
    regs->gpr[1] = tramp_r1;
    regs->nip    = tramp_nip;

    return 0;

sigill:
    force_sig(SIGILL);
    return -1;
}

static bool is_bl_insn(u32 insn)
{
    /* opcode=18, AA=bit[1]=0, LK=bit[0]=1 */
    return (insn >> 26) == 18 && (insn & 3) == 1;
}

static unsigned long bl_target(unsigned long pc, u32 insn)
{
    /* 26-bit signed byte offset in bits[25:2]; bit 25 is sign bit */
    s32 offset = (s32)(insn & 0x03FFFFFC);

    if (offset & 0x02000000)
        offset |= (s32)0xFC000000;
    return pc + (long)offset;
}

static u32 make_bl(unsigned long from, unsigned long to)
{
    long delta = (long)(to - from);

    /* opcode=18, offset in bits[25:2], AA=0, LK=1 */
    return (18 << 26) | ((u32)(delta & 0x03FFFFFC)) | 1;
}

static int copy_from_vaddr(struct mm_struct *mm, unsigned long vaddr,
                           void *dst, int len)
{
    unsigned int gup_flags = FOLL_FORCE | FOLL_SPLIT_PMD;
    struct vm_area_struct *vma;
    struct page *page;

    page = get_user_page_vma_remote(mm, vaddr, gup_flags, &vma);
    if (IS_ERR(page))
        return PTR_ERR(page);
    uprobe_copy_from_page(page, vaddr, dst, len);
    put_page(page);
    return 0;
}

enum {
    OPT_BL,      /* installing bl   — current insn must be trap (swbp) */
    UNOPT_TRAP,  /* restoring trap  — current insn must be bl           */
};

struct write_opcode_ctx {
    unsigned long base;
    int           update;
};

static int verify_insn(struct page *page, unsigned long vaddr,
                       uprobe_opcode_t *new_opcode, int nbytes, void *data)
{
    struct write_opcode_ctx *ctx = data;
    u32 current_insn;

    uprobe_copy_from_page(page, ctx->base, &current_insn, sizeof(u32));

    switch (ctx->update) {
    case OPT_BL:
        return is_swbp_insn((uprobe_opcode_t *)&current_insn) ? 1 : -1;
    case UNOPT_TRAP:
        return is_bl_insn(current_insn) ? 1 : -1;
    }
    return -1;
}

static int write_insn(struct arch_uprobe *auprobe, struct vm_area_struct *vma,
                      unsigned long vaddr, uprobe_opcode_t *insn, int nbytes,
                      void *ctx)
{
    return uprobe_write(auprobe, vma, vaddr, insn, nbytes,
                        verify_insn,
                        true  /* is_register     */,
                        false /* do_update_ref_ctr */,
                        ctx);
}

static int swbp_optimize(struct arch_uprobe *auprobe, struct vm_area_struct *vma,
                         unsigned long vaddr, unsigned long tramp_vaddr)
{
    struct write_opcode_ctx ctx = { .base = vaddr, .update = OPT_BL };
    u32 bl_insn = make_bl(vaddr, tramp_vaddr);

    /* trap and bl are both 4-byte aligned on powerpc; one write suffices */
    return write_insn(auprobe, vma, vaddr,
                      (uprobe_opcode_t *)&bl_insn, sizeof(u32), &ctx);
}

static int swbp_unoptimize(struct arch_uprobe *auprobe, struct vm_area_struct *vma,
                           unsigned long vaddr)
{
    struct write_opcode_ctx ctx = { .base = vaddr, .update = UNOPT_TRAP };
    uprobe_opcode_t trap = UPROBE_SWBP_INSN;

    return write_insn(auprobe, vma, vaddr, &trap, sizeof(u32), &ctx);
}

static bool can_optimize(struct arch_uprobe *auprobe, unsigned long vaddr)
{
    /* Only optimize probes on the 4-byte NOP (0x60000000) USDT marker */
    return *(u32 *)auprobe->insn == PPC_RAW_NOP() && !(vaddr & 3);
}

static bool should_optimize(struct arch_uprobe *auprobe)
{
    return !test_bit(ARCH_UPROBE_FLAG_OPTIMIZE_FAIL, &auprobe->flags) &&
            test_bit(ARCH_UPROBE_FLAG_CAN_OPTIMIZE,  &auprobe->flags);
}

static bool __is_optimized(u32 insn, unsigned long vaddr)
{
    if (!is_bl_insn(insn))
        return false;
    return __in_uprobe_trampoline(bl_target(vaddr, insn));
}

static int is_optimized(struct mm_struct *mm, unsigned long vaddr, bool *optimized)
{
    u32 insn;
    int err;

    err = copy_from_vaddr(mm, vaddr, &insn, sizeof(u32));
    if (err)
        return err;
    *optimized = __is_optimized(insn, vaddr);
    return 0;
}

/* set_swbp/set_orig_insn: skip redundant writes when probe is optimized */
int set_swbp(struct arch_uprobe *auprobe, struct vm_area_struct *vma,
             unsigned long vaddr)
{
    if (should_optimize(auprobe)) {
        bool optimized = false;
        int  err;

        err = is_optimized(vma->vm_mm, vaddr, &optimized);
        if (err)
            return err;
        if (optimized)
            return 0;
    }
    return uprobe_write_opcode(auprobe, vma, vaddr,
                               UPROBE_SWBP_INSN, true /* is_register */);
}

int set_orig_insn(struct arch_uprobe *auprobe, struct vm_area_struct *vma,
                  unsigned long vaddr)
{
    if (test_bit(ARCH_UPROBE_FLAG_CAN_OPTIMIZE, &auprobe->flags)) {
        struct mm_struct *mm = vma->vm_mm;
        bool optimized = false;
        int  err;

        err = is_optimized(mm, vaddr, &optimized);
        if (err)
            return err;
        if (optimized)
            WARN_ON_ONCE(swbp_unoptimize(auprobe, vma, vaddr));
    }
    return uprobe_write_opcode(auprobe, vma, vaddr,
                               *(uprobe_opcode_t *)&auprobe->insn,
                               false /* is_register */);
}

static int __arch_uprobe_optimize(struct arch_uprobe *auprobe,
                                  struct mm_struct *mm, unsigned long vaddr)
{
    struct uprobe_trampoline *tramp;
    struct vm_area_struct *vma;
    bool new = false;
    int  err;

    vma = find_vma(mm, vaddr);
    if (!vma)
        return -EINVAL;

    tramp = get_uprobe_trampoline(vaddr, &new);
    if (!tramp)
        return -EINVAL;

    err = swbp_optimize(auprobe, vma, vaddr, tramp->vaddr);
    if (WARN_ON_ONCE(err) && new)
        destroy_uprobe_trampoline(tramp);
    return err;
}

void arch_uprobe_optimize(struct arch_uprobe *auprobe, unsigned long vaddr)
{
    struct mm_struct *mm = current->mm;
    u32 insn;

    if (!should_optimize(auprobe))
        return;

    mmap_write_lock(mm);

    /* Recheck: another thread may have optimized while we waited for lock */
    if (copy_from_vaddr(mm, vaddr, &insn, sizeof(u32)))
        goto unlock;
    if (!is_swbp_insn((uprobe_opcode_t *)&insn))
        goto unlock;

    if (__arch_uprobe_optimize(auprobe, mm, vaddr))
        set_bit(ARCH_UPROBE_FLAG_OPTIMIZE_FAIL, &auprobe->flags);

unlock:
    mmap_write_unlock(mm);
}

#endif /* CONFIG_PPC64 */

/**
 * is_trap_insn - check if the instruction is a trap variant
 * @insn: instruction to be checked.
 * Returns true if @insn is a trap variant.
 */
bool is_trap_insn(uprobe_opcode_t *insn)
{
	return (is_trap(*insn));
}

/**
 * arch_uprobe_analyze_insn
 * @mm: the probed address space.
 * @arch_uprobe: the probepoint information.
 * @addr: vaddr to probe.
 * Return 0 on success or a -ve number on error.
 */
int arch_uprobe_analyze_insn(struct arch_uprobe *auprobe,
		struct mm_struct *mm, unsigned long addr)
{
	if (addr & 0x03)
		return -EINVAL;

	if (cpu_has_feature(CPU_FTR_ARCH_31) &&
	    ppc_inst_prefixed(ppc_inst_read(auprobe->insn)) &&
	    (addr & 0x3f) == 60) {
		pr_info_ratelimited("Cannot register a uprobe on 64 byte unaligned prefixed instruction\n");
		return -EINVAL;
	}

	if (!can_single_step(ppc_inst_val(ppc_inst_read(auprobe->insn)))) {
		pr_info_ratelimited("Cannot register a uprobe on instructions that can't be single stepped\n");
		return -ENOTSUPP;
	}
#ifdef CONFIG_PPC64
	/* Flag 4-byte NOP probes as eligible for bl optimization */
	if (can_optimize(auprobe, addr))
		set_bit(ARCH_UPROBE_FLAG_CAN_OPTIMIZE, &auprobe->flags);
#endif
	return 0;
}

/*
 * arch_uprobe_pre_xol - prepare to execute out of line.
 * @auprobe: the probepoint information.
 * @regs: reflects the saved user state of current task.
 */
int arch_uprobe_pre_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	struct arch_uprobe_task *autask = &current->utask->autask;

	autask->saved_trap_nr = current->thread.trap_nr;
	current->thread.trap_nr = UPROBE_TRAP_NR;
	regs_set_return_ip(regs, current->utask->xol_vaddr);

	user_enable_single_step(current);
	return 0;
}

/**
 * uprobe_get_swbp_addr - compute address of swbp given post-swbp regs
 * @regs: Reflects the saved state of the task after it has hit a breakpoint
 * instruction.
 * Return the address of the breakpoint instruction.
 */
unsigned long uprobe_get_swbp_addr(struct pt_regs *regs)
{
	return instruction_pointer(regs);
}

/*
 * If xol insn itself traps and generates a signal (SIGILL/SIGSEGV/etc),
 * then detect the case where a singlestepped instruction jumps back to its
 * own address. It is assumed that anything like do_page_fault/do_trap/etc
 * sets thread.trap_nr != UINT_MAX.
 *
 * arch_uprobe_pre_xol/arch_uprobe_post_xol save/restore thread.trap_nr,
 * arch_uprobe_xol_was_trapped() simply checks that ->trap_nr is not equal to
 * UPROBE_TRAP_NR == UINT_MAX set by arch_uprobe_pre_xol().
 */
bool arch_uprobe_xol_was_trapped(struct task_struct *t)
{
	if (t->thread.trap_nr != UPROBE_TRAP_NR)
		return true;

	return false;
}

/*
 * Called after single-stepping. To avoid the SMP problems that can
 * occur when we temporarily put back the original opcode to
 * single-step, we single-stepped a copy of the instruction.
 *
 * This function prepares to resume execution after the single-step.
 */
int arch_uprobe_post_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	struct uprobe_task *utask = current->utask;

	WARN_ON_ONCE(current->thread.trap_nr != UPROBE_TRAP_NR);

	current->thread.trap_nr = utask->autask.saved_trap_nr;

	/*
	 * On powerpc, except for loads and stores, most instructions
	 * including ones that alter code flow (branches, calls, returns)
	 * are emulated in the kernel. We get here only if the emulation
	 * support doesn't exist and have to fix-up the next instruction
	 * to be executed.
	 */
	regs_set_return_ip(regs, (unsigned long)ppc_inst_next((void *)utask->vaddr, auprobe->insn));

	user_disable_single_step(current);
	return 0;
}

/* callback routine for handling exceptions. */
int arch_uprobe_exception_notify(struct notifier_block *self,
				unsigned long val, void *data)
{
	struct die_args *args = data;
	struct pt_regs *regs = args->regs;

	/* regs == NULL is a kernel bug */
	if (WARN_ON(!regs))
		return NOTIFY_DONE;

	/* We are only interested in userspace traps */
	if (!user_mode(regs))
		return NOTIFY_DONE;

	switch (val) {
	case DIE_BPT:
		if (uprobe_pre_sstep_notifier(regs))
			return NOTIFY_STOP;
		break;
	case DIE_SSTEP:
		if (uprobe_post_sstep_notifier(regs))
			return NOTIFY_STOP;
		break;
	default:
		break;
	}
	return NOTIFY_DONE;
}

/*
 * This function gets called when XOL instruction either gets trapped or
 * the thread has a fatal signal, so reset the instruction pointer to its
 * probed address.
 */
void arch_uprobe_abort_xol(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	struct uprobe_task *utask = current->utask;

	current->thread.trap_nr = utask->autask.saved_trap_nr;
	instruction_pointer_set(regs, utask->vaddr);

	user_disable_single_step(current);
}

/*
 * See if the instruction can be emulated.
 * Returns true if instruction was emulated, false otherwise.
 */
bool arch_uprobe_skip_sstep(struct arch_uprobe *auprobe, struct pt_regs *regs)
{
	int ret;

	/*
	 * emulate_step() returns 1 if the insn was successfully emulated.
	 * For all other cases, we need to single-step in hardware.
	 */
	ret = emulate_step(regs, ppc_inst_read(auprobe->insn));
	if (ret > 0)
		return true;

	return false;
}

unsigned long
arch_uretprobe_hijack_return_addr(unsigned long trampoline_vaddr, struct pt_regs *regs)
{
	unsigned long orig_ret_vaddr;

	orig_ret_vaddr = regs->link;

	/* Replace the return addr with trampoline addr */
	regs->link = trampoline_vaddr;

	return orig_ret_vaddr;
}

bool arch_uretprobe_is_alive(struct return_instance *ret, enum rp_check ctx,
				struct pt_regs *regs)
{
	if (ctx == RP_CHECK_CHAIN_CALL)
		return regs->gpr[1] <= ret->stack;
	else
		return regs->gpr[1] < ret->stack;
}

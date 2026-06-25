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
#include <linux/kdebug.h>

#include <asm/sstep.h>
#include <asm/inst.h>

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

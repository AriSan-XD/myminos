#ifndef __MOAT_BPF_H__
#define __MOAT_BPF_H__

#include <minos/types.h>
#include <minos/list.h>
#include <virt/vm.h>

#define PAR_PA_MSK (0x3ffffffUL << 12)

#define CONFIG_MAX_MOAT_BPF	(CONFIG_MAX_VM - 1)

struct moat_prog
{
	uint32_t vmid;
	struct mm_struct mm;
	struct list_head list;
};

extern struct moat_prog *moat_progs[CONFIG_MAX_MOAT_BPF];

static inline struct moat_prog *get_moat_prog_by_id(uint32_t vmid)
{
	if (unlikely(vmid >= CONFIG_MAX_MOAT_BPF) || unlikely(vmid == 0))
		return NULL;
	return moat_progs[vmid];
};

int moat_mmap(struct moat_prog *prog, unsigned long base, size_t size);
int moat_bpf_mmap(unsigned long ipa, unsigned long size, uint32_t vmid);
int moat_bpf_create(void);

#endif
#ifndef __MOAT_BPF_H__
#define __MOAT_BPF_H__

#include <minos/types.h>
#include <minos/list.h>
#include <virt/vm.h>

#define IPA_VMID_SHIFT		(48)
#define IPA_VMID_MSK		(0xffffUL << IPA_VMID_SHIFT)

#define PAGE_DESC_ADDR_MASK	(0x0000fffffffff000UL)
#define PAR_PA_MSK			(0x3ffffffUL << 12)
#define S2_PHYSICAL_MASK	(0x0000fffffffff000UL)

#define CONFIG_MAX_MOAT_BPF	(CONFIG_MAX_VM - 1)

struct moat_prog
{
	uint32_t vmid;
	struct mm_struct mm;
	struct list_head list;
};

extern struct moat_prog *moat_progs[CONFIG_MAX_MOAT_BPF];
extern struct list_head moat_prog_list;

static inline struct moat_prog *get_moat_prog_by_id(uint32_t vmid)
{
	if (unlikely(vmid >= CONFIG_MAX_MOAT_BPF) || unlikely(vmid == 0))
		return NULL;
	
	struct moat_prog *prog;
	list_for_each_entry(prog, &moat_prog_list, list)
	{
		if (prog->vmid == vmid)
			return prog;
	}
	// return moat_progs[vmid];
	return NULL;
};

int moat_bpf_create(void);
int moat_bpf_destroy(unsigned int vmid);
int moat_alloc_mmap(struct mm_struct *mm, unsigned long base, size_t size);
int moat_bpf_mmap(unsigned long ipa, unsigned long size, uint32_t vmid, bool shared);
int moat_bpf_unmmap(unsigned long ipa, unsigned long size, uint32_t vmid, bool shared);
void moat_bpf_switch_to(uint32_t vmid);
void moat_bpf_switch_back(void);
int moat_bpf_memcpy(void *dest, const void *src, size_t n, unsigned int vmid);

#endif
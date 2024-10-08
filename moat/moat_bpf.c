#include <moat/moat_bpf.h>
#include <minos/print.h>
#include <virt/vm.h>

uint64_t original_vttbr;
LIST_HEAD(moat_prog_list);
struct moat_prog *moat_progs[CONFIG_MAX_MOAT_BPF];

int prints2(uint64_t base, int depth);

static uint64_t get_host_vttbr(void)
{
	void *pgdp;
	uint64_t current_vttbr, host_vttbr;
	struct vm *vm = get_host_vm();
	pgdp = vm->mm.pgdp;
	current_vttbr = read_sysreg(VTTBR_EL2);
	host_vttbr = vtop(pgdp) | ((uint64_t)vm->vmid << 48);
	pr_debug("current vttbr: %lx, host vttbr: %lx\n", current_vttbr, host_vttbr);
	return host_vttbr;
}

/* insert vmid to ipa when doing mapping */
static unsigned long insert_vmid_to_ipa(unsigned long ipa, uint32_t vmid)
{
	return (ipa | ((uint64_t)vmid << IPA_VMID_SHIFT));
}

/* extract vmid from ipa, then use vmid to find prog and translate ipa to pa*/
static int ipa_to_pa_vmid(unsigned long ipa, unsigned long *pa, unsigned int vmid)
{
	// unsigned int vmid;
	struct mm_struct *mm;
	// void *pgdp;
	
	// vmid = (ipa & IPA_VMID_MSK) >> IPA_VMID_SHIFT;

	if (vmid == 1)
	{
		mm = &(get_host_vm()->mm);

		return translate_guest_ipa(mm, ipa, pa);
	}
	else
	{	
		struct moat_prog *prog;

		prog = get_moat_prog_by_id(vmid);
		mm = &prog->mm;
		if (!prog)
		{
			pr_err("[%s] no moat prog of vmid: %d\n", __func__, vmid);
			return -ENOPROG;
		}
			
		return translate_guest_ipa(mm, ipa, pa);
	}
}

static int do_moat_mmap(struct mm_struct *mm, virt_addr_t vir, phy_addr_t phy, size_t size)
{
	unsigned long tmp;
	int ret;

	tmp = BALIGN(vir + size, PAGE_SIZE);
	vir = ALIGN(vir, PAGE_SIZE);
	phy = ALIGN(phy, PAGE_SIZE);
	size = tmp - vir;
	
	spin_lock(&mm->lock);
	ret = arch_guest_map(mm, vir, vir + size, phy, VM_NORMAL | VM_RWX);
	spin_unlock(&mm->lock);
	if (ret)
	{
		pr_err("%s failed\n", __func__);
		return ret;
	}
	
	return 0;
}

static int do_moat_unmmap(struct moat_prog *prog, virt_addr_t vir, size_t size, bool shared)
{
	struct mm_struct *mm = &prog->mm;
	unsigned long end;
	int ret;

	if (!IS_PAGE_ALIGN(vir) || !IS_PAGE_ALIGN(size)) {
		pr_warn("WARN: destroy guest mapping [0x%x 0x%x]\n",
				vir, vir + size);
		end = PAGE_BALIGN(vir + size);
		vir = PAGE_ALIGN(vir);
		size = end - vir;
	}
	
	spin_lock(&mm->lock);
	ret = arch_guest_unmap(mm, vir, vir + size);
	spin_unlock(&mm->lock);
	if (ret)
	{
		pr_err("%s failed\n", __func__);
		return ret;
	}
	
	if (!shared)
		free_pages((void *)vir);
	
	return 0;
}

/*
 * offset - the base address need to be mapped
 * size - the size need to mapped
 */
int moat_alloc_mmap(struct mm_struct *mm, unsigned long ipa, size_t size)
{
	int ret;
	int nr_pages;
	unsigned long start, pstart;
	
	nr_pages = PAGE_NR(size);
	start = (unsigned long)get_free_pages(nr_pages);
	if (!start)
	{
		pr_err("no memory for moat prog\n");
		return -ENOMEM;
	}
	pstart = vtop(start);

	pr_info("%s pstart:0x%x size:0x%x\n", __func__, pstart, size);
	ret = do_moat_mmap(mm, ipa, pstart, size);
	if (ret)
	{
		pr_err("mmap failed\n");
		free_pages((void *)pstart);
		return -EFAULT;
	}

	return 0;
}

/* hypercall: MOAT_BPF_MMAP */
int moat_bpf_mmap(unsigned long ipa, unsigned long size, uint32_t vmid, bool shared)
{
	struct moat_prog *prog;
	// uint64_t vttbr = 0; 
	int ret;

	prog = get_moat_prog_by_id(vmid);
	if (prog == NULL)
	{
		pr_err("[%s] no moat prog of vmid: %d\n", __func__, vmid);
		return -ENOPROG;
	}

	if (shared)
	{
		unsigned long pstart;
		if (ipa_to_pa_vmid(ipa, &pstart, 1))	// 1 is host vmid, using it to get pa
		{
			pr_err("ipa_to_pa_vmid of vmid 1 failed\n");
			return -EFAULT;
		}
		pr_info("shared mapping, ipa: 0x%lx, pa: 0x%lx, size: 0x%lx\n", ipa, pstart, size);
		ret = do_moat_mmap(&prog->mm, ipa, pstart, size);
	}
	else
	{
		pr_info("non-shared mapping\n");
		ret = moat_alloc_mmap(&prog->mm, ipa, size);
	}

	if (!ret) {
		pr_info("moat_bpf_mmap successed size: 0x%x, ipa: 0x%lx, vmid: %d\n", size, ipa, vmid);

		return 0;
	}

	return -EINVAL;
}

/* hypercall: MOAT_BPF_UNMMAP */
int moat_bpf_unmmap(unsigned long ipa, unsigned long size, uint32_t vmid, bool shared)
{
	struct moat_prog *prog;
	int ret;
	
	pr_info("Invoke moat_bpf_unmmap, ipa:0x%x, size:0x%x, vmid:%d\n", 
			ipa, size, vmid);

	prog = get_moat_prog_by_id(vmid);
	if (prog == NULL)
	{
		pr_err("[%s] no moat prog of vmid: %d\n", __func__, vmid);
		return -ENOPROG;
	}

	ret = do_moat_unmmap(prog, ipa, size, shared);
	if (!ret)
		pr_info("moat_bpf_unmmap successed size: 0x%x, at ipa 0x%p\n", size, ipa);
	else	
	{
		pr_err("moat_bpf_unmmap failed\n");
		return -EFAULT;
	}

	return 0;
}

/* hypercall: HVC_MOAT_CREATE */
int moat_bpf_create(void)
{
	uint64_t vttbr = 0;
	struct moat_prog *prog;
	struct mm_struct *mm;

	/* for test, suppose to be done in init */
	memset(moat_progs, 0, sizeof(moat_progs));
	
	prog = malloc(sizeof(struct moat_prog));
	if (!prog)
		return -ENOMEM;
	memset(prog, 0, sizeof(struct moat_prog));
	
	prog->mm.is_moat = true;
	
	original_vttbr = read_vttbr_el2();
	pr_info("original vttbr: %lx\n", original_vttbr);

	/* reuse the vmid allocation, up tp CONFIG_MAX_VM(64) */
	prog->vmid = alloc_new_vmid();
	pr_info("allocated vmid: %d\n", prog->vmid);
	if (prog->vmid == 0)
	{
		pr_err("vm allocated failed\n");	
		return -ENOVMID;
	}

	mm = &prog->mm;
	mm->pgdp = NULL;
	spin_lock_init(&mm->lock);

	/* allocate stage-2 pgd for this BPF */
	mm->pgdp = arch_alloc_guest_pgd();
	if (mm->pgdp == NULL)
	{
		pr_err("No memory for vm page table\n");
		return -ENOMEM;
	}

	init_list(&prog->list);
	list_add_tail(&moat_prog_list, &prog->list);
	moat_progs[prog->vmid] = prog;

	vttbr = vtop(mm->pgdp) | ((uint64_t)prog->vmid << 48);

	pr_info("allocated stage-2 pgd at: %lx, vttbr: %lx for vmid: %d\n", 
			mm->pgdp, vttbr, prog->vmid);

	pr_info("host vttbr: %lx\n", get_host_vttbr());
	
	return prog->vmid;
}

static int do_moat_bpf_destroy(void *pfn, int depth)
{
	int i = 0;
	
	if (depth > 2)
		return 0;
	for(i = 0; i < 512; i++)
	{
		pte_t *pte = (pte_t *)pfn + i;
		if ((*pte) & 1)
		{
			pte_t *child = (pte_t *)(*pte & S2_PHYSICAL_MASK);
			
			if ((*pte) & 2)
				do_moat_bpf_destroy(child, depth + 1);
			free_pages(child);
			WRITE_ONCE(*pte, 0);
			__dsb(ishst);
		}
	}
	return 0;
}

/* hypercall: HVC_MOAT_DESTROY */
int moat_bpf_destroy(unsigned int vmid)
{
	void *pgdp;
	struct moat_prog *prog;
	struct mm_struct *mm;
	
	prog = get_moat_prog_by_id(vmid);
	if (!prog)
	{
		pr_err("[%s] no moat prog of vmid: %d\n", __func__, vmid);
		return -ENOPROG;
	}
	
	mm = &prog->mm;
	pgdp = mm->pgdp;

	do_moat_bpf_destroy(pgdp, 0);

	list_del(&prog->list);
	free(prog);

	destroy_vmid(vmid);
	
	return 0;
}

void *copy_page(void *src)
{
	int i;
	void *new_page = get_free_page();

	// print the content of the page
	pr_info("src: 0x%lx page content:\n", (u64)src);
	for (i = 0; i < 512; i++)
	{
		u64 pte = *((u64 *)src + i);
		if (pte & 1)
			pr_info("%d: pte: 0x%lx\n",i , pte);
	}

	memcpy(new_page, (void *)src, PAGE_SIZE);

	pr_info("new page: 0x%lx content:\n", (u64)new_page);
	for (i = 0; i < 512; i++)
	{
		u64 pte = *((u64 *)new_page + i);
		if (pte & 1)
			pr_info("%d: pte: 0x%lx\n",i , pte);
	}

	return new_page;
}

/* hypercall: HVC_MOAT_SWITCH_TO */
void moat_bpf_switch_to(uint32_t vmid)
{
	uint64_t vttbr = 0;
	uint64_t pgdp;
	struct moat_prog *prog;
	unsigned long flags;
	
	prog = get_moat_prog_by_id(vmid);
	if (!prog)
	{
		pr_err("[%s] no moat prog of vmid: %d\n", __func__, vmid);
		return;
	}
	pgdp = vtop(prog->mm.pgdp);
	vttbr = pgdp | ((uint64_t)vmid << 48);

	pr_info("vttbr before switch: %lx\n", read_sysreg(VTTBR_EL2));
	pr_info("trying to switch vttbr\n");
	
	local_irq_save(flags);

	write_vttbr_el2(vttbr);	
	pr_info("current vttbr: %lx\n", read_sysreg(VTTBR_EL2));

	local_irq_restore(flags);
}

/* hypercall: HVC_MOAT_SWITCH_BACK */
void moat_bpf_switch_back(void)
{
	write_vttbr_el2(original_vttbr);
	pr_info("vttbr switched back\n");
	pr_info("current vttbr: %lx\n", read_sysreg(VTTBR_EL2));
}

/* 
* hypercall: HVC_MOAT_MEMCPY 
* input: ipa
*/
int moat_bpf_memcpy(void *dest, const void *src, size_t n, unsigned int vmid)
{
	unsigned long pa_dest, pa_src;
	ipa_to_pa_vmid((unsigned long)dest, &pa_dest, vmid);
	ipa_to_pa_vmid((unsigned long)src, &pa_src, vmid);
	pr_info("copy 0x%lx of size 0x%lx to 0x%lx\n", (unsigned long)src, n, (unsigned long)dest);
	pr_info("pa_dest: %lx, pa_src: %lx\n", (unsigned long)pa_dest, (unsigned long)pa_src);
	memcpy((void *)pa_dest, (void *)pa_src, n);
	// maybe can use copy_from_guest(), but maybe the original s2pt do not have mapping
	return 0;
}

int prints2(uint64_t base, int depth)
{
	int i = 0;
    if (depth > 2)
        return 0;
    uint64_t *pagetable = (uint64_t *)base;
	if (depth == 0)
	    pr_info("base: 0x%lx\n", base);
    for (i = 0; i < 512; i++)
    {
        uint64_t pte = pagetable[i];
        if (pte & 1)
        {
            // printk("pte: 0x%lx\n", pte);
            uint64_t child = pte & ((uint64_t)0xfffffffff << 12);
            if (depth == 0)
                pr_info("..%d: pte 0x%lx pa 0x%lx\n", i, pte, child);
            else if (depth == 1)
                pr_info(".. ..%d: pte 0x%lx pa 0x%lx\n", i, pte, child);
            else if (depth == 2)
                pr_info(".. .. ..%d: pte 0x%lx pa 0x%lx\n", i, pte, child);
            if (pte & 2)
                prints2(child, depth + 1);
        }
    }
    return 0;
}
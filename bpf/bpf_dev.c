#include <bpf/bpf_dev.h>
#include <minos/print.h>
#include <virt/vm.h>

unsigned long prints2(uint64_t base, int depth);

unsigned long bpf_dev_mmap(void)
{
	struct vm *vm = get_host_vm();
	unsigned long ret = 114514;
	unsigned long vttbr = 0;
	unsigned long lvl_0_pa = 0;
	unsigned long content = 0;
	asm volatile("mrs %0, vttbr_el2": "=r"(vttbr)::);
	pr_notice("vttbr_el2: %lx\n", vttbr);
	lvl_0_pa = ((((vttbr >> 1) >> 7) & 0xfffffffff) << 8);
	asm volatile("ldr %0, [%1]": "=r"(content):"r"(lvl_0_pa):"memory");
	pr_notice("content of vttbr_el2: %lx\n", content);
	ret = create_guest_mapping(&vm->mm, 0xb0000000, 0xb0000000, 
			0x2000, VM_NORMAL | VM_RW);
	if (ret)
		pr_err("map S2PT for guest failed\n");
	else
		pr_notice("map S2PT for guest success\n");
	return ret;
}

unsigned long bpf_dev_create(void)
{
	struct vm *vm = get_host_vm();
	unsigned long ret = 114514;
	unsigned long vttbr = 0;
	unsigned long lvl_0_pa = 0;
	unsigned long content = 0;
	asm volatile("mrs %0, vttbr_el2": "=r"(vttbr)::);
	pr_notice("vttbr_el2: %lx\n", vttbr);
	lvl_0_pa = ((((vttbr >> 1) >> 7) & 0xfffffffff) << 8);
	asm volatile("ldr %0, [%1]": "=r"(content):"r"(lvl_0_pa):"memory");
	pr_notice("content of vttbr_el2: %lx\n", content);
	ret = prints2(lvl_0_pa, 0);
	
	return ret;
}

unsigned long prints2(uint64_t base, int depth)
{
	int i = 0;
    if (depth > 1)
        return 0;
    uint64_t *pagetable = (uint64_t *)base;
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
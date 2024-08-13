#include <bpf/bpf_dev.h>
#include <minos/print.h>

unsigned long bpf_dev_create(void)
{
    unsigned long ret = 114514;
    unsigned long vttbr = 0;
    unsigned long lvl_0_pa = 0;
    asm volatile("mrs %0, vttbr_el2": "=r"(vttbr)::);
    pr_notice("vttbr_el2: %lx\n", ret);
    lvl_0_pa = ((((vttbr >> 1) >> 7) & 0xfffffffff) << 8);
    asm volatile("ldr %0, [%1]": "=r"(ret):"r"(lvl_0_pa):"memory");
    pr_notice("content of vttbr_el2: %lx\n", ret);
    return ret;
}
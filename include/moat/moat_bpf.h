#ifndef __MOAT_BPF_H__
#define __MOAT_BPF_H__

#include <linux/types.h>


struct moat_prog
{
    uint32_t vmid;
    void *pgdp;
    struct list_head list;
};

unsigned long moat_bpf_mmap(void);
unsigned long moat_bpf_create(void);

#endif
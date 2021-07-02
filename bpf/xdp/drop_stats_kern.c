/* SPDX-License-Identifier: GPL-2.0 */
/**
 * How to:
 * ------------------------------------------------------------------------------------------------
 * compile program: clang -O2 -target bpf -c drop_stats_kern.c -o drop_stats_kern.o
 * 
 * load program: bpftool prog drop_stats_kern.o /sys/fs/bpf/tpstat/drop_stats_kern
 * 
 * attach program: bpftool net attach xdpgeneric pinned /sys/fs/bpf/tpstat/drop_stats_kern dev eth0
 * 
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* This is the data record stored in the map */
struct datarec {
	__u64 rx_packets;
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

SEC("xdp_stats1")
int  xdp_stats1_func(struct xdp_md *ctx)
{
	// void *data_end = (void *)(long)ctx->data_end;
	// void *data     = (void *)(long)ctx->data;
	struct datarec *rec;
	__u32 key = XDP_DROP; 

	/* Lookup in kernel BPF-side return pointer to actual data record */
	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (!rec)
		return XDP_ABORTED;

	/* Multiple CPUs can access data record. Thus, the accounting needs to
	 * use an atomic operation.
	 */
	lock_xadd(&rec->rx_packets, 1);
       
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
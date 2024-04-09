#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif

// #ifndef USES_BPF_MAP_UPDATE_ELEM
// #define USES_BPF_MAP_UPDATE_ELEM
// #endif

#include <linux/in.h>
#include <linux/if_ether.h>
#include "xdp_fw_kern.h"

SEC("xdp_fw")
int xdp_fw_prog(struct xdp_md *ctx) {
	void* data_end = (void*)(long)ctx->data_end;
	void* data = (void*)(long)ctx->data;

	struct ethhdr *eth;
	struct iphdr *ip;
	// struct udphdr *l4;

	uint64_t nh_off = 0;
	__u64 *value;

	eth = data;
	nh_off = sizeof(*eth);

	// Check if enough space for ethernet header
	if (data + nh_off > data_end)
		return XDP_DROP;

	// Check if ethernet protocol is IP
	if(eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_DROP;

	ip = data + nh_off;
	nh_off += sizeof(*ip);

	// Check if enough space for IP Header
	if (data + nh_off > data_end)
		return XDP_DROP;
	
	// Check if protocol is TCP
	if (ip->protocol != IPPROTO_TCP)
		return XDP_DROP;

	value = bpf_map_lookup_elem(&blacklist, &ip->saddr);
	if (value)
		return XDP_DROP;

	return XDP_PASS;
}

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include <stdlib.h>
int main(int argc, char** argv) {
	BPF_MAP_INIT(&blacklist, "blacklist_map", "", "");

	__u32 key;
	__u64 value;

	klee_make_symbolic(&key, sizeof(__u32), "blocked_addr");
	klee_make_symbolic(&value, sizeof(__u64), "value");
	klee_assume((key < 10));
	klee_assume((value < 20));

	// if (bpf_map_update_elem(&blacklist, &key, &value, BPF_ANY) < 0)
  //   return -1;
	
	struct pkt *pkt = malloc(sizeof(struct pkt));
	klee_make_symbolic(pkt, sizeof(struct pkt), "user_pkt");
	pkt->ether.h_proto = bpf_htons(ETH_P_IP);
	pkt->ipv4.protocol = IPPROTO_TCP;

	struct xdp_md test;
  test.data = (long)(&(pkt->ether));
  test.data_end = (long)(pkt + 1);
  test.data_meta = 0;
  test.ingress_ifindex = 0;
  test.rx_queue_index = 0;

	bpf_begin();
	if (xdp_fw_prog(&test))
		return 1;
	return 0;
}

#endif
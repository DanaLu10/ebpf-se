#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif

#ifndef USES_BPF_CSUM_DIFF
#define USES_BPF_CSUM_DIFF
#endif

// #ifndef USES_BPF_MAP_UPDATE_ELEM
// #define USES_BPF_MAP_UPDATE_ELEM
// #endif

#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../common/parsing_helpers.h"
#include "../common/debug_tags.h"
#include "klee/klee.h"

/*
	Simple Static NAT implementation, with a one-to-one mapping of inner IP address to 
	outer IP address
*/

// TODO: think about if we need to decrement ttl

struct bpf_map_def SEC("maps") inner_to_outer_udp = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 16,
};

struct bpf_map_def SEC("maps") outer_to_inner_udp = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 16,
};

struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[100];
};

// static mapping
SEC("xdp")
int xdp_nat_inner_to_outer(struct xdp_md *ctx) {
	void* data_end = (void*)(long)ctx->data_end;
	void* data = (void*)(long)ctx->data;

	struct ethhdr *eth;
	struct iphdr *ip;
	struct tcphdr *tcphdr;

	uint64_t nh_off = 0;
	__u32 addr;
	__u32 csum;
	__u32 *value_ptr;

	eth = data;
	nh_off = sizeof(*eth);
	if (data  + nh_off  > data_end)
		return XDP_DROP;

	// TODO: may want to return pass instead?
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_DROP;
	
	ip = data + nh_off;
	nh_off += sizeof(*ip);

	// Check if enough space for IP Header
	if (data + nh_off > data_end)
		return XDP_DROP;
	
	addr = ip->saddr;
	value_ptr = bpf_map_lookup_elem(&inner_to_outer_udp, &addr);

	// Our static mapping does not contain an entry for this address
	if (value_ptr == NULL)
		return XDP_DROP;

	ip->saddr = *value_ptr;

	// Update IP checksum (using formula from https://datatracker.ietf.org/doc/html/rfc1624)
	ip->check = 0;
	csum = bpf_csum_diff(0, 0, (__be32 *)ip, sizeof(*ip), 0);
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
	ip->check = ~csum;

	// TODO: check this? If redirect, where to redirect to. Can we use TX instead of REDIRECT?
	// return bpf_redirect(, 0);
	return XDP_TX;
}

int main(int argc, char** argv) {
	BPF_MAP_INIT(&inner_to_outer_udp, "inner_to_outer_udp_map", "", "");
	BPF_MAP_INIT(&outer_to_inner_udp, "outer_to_inner_udp_map", "", "");

	__u32 key = 10;
	__u32 value = 42;

	// if(bpf_map_update_elem(&inner_to_outer_udp, &key, &value, 0) < 0)
  //   return -1;

	struct pkt *pkt = malloc(sizeof(struct pkt));
	klee_make_symbolic(pkt, sizeof(struct pkt), "user_pkt");
	pkt->ether.h_proto = bpf_htons(ETH_P_IP);

	struct xdp_md test;
  test.data = (long)(&(pkt->ether));
  test.data_end = (long)(pkt + 1);
  test.data_meta = 0;
  test.ingress_ifindex = 0;
  test.rx_queue_index = 0;

	bpf_begin();
	if (xdp_nat_inner_to_outer(&test))
		return 1;
	return 0;

	// symbolic packet
	// map with some rules
	// assuming the contents of the packet, assert a particular action the program returns
}
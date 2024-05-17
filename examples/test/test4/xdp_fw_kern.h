#ifndef __XDP_MAP_H
#define __XDP_MAP_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../../common/parsing_helpers.h"
#include "../../common/debug_tags.h"

struct bpf_map_def SEC("maps") blacklist = {
	.type = BPF_MAP_TYPE_ARRAY,
	.value_size = sizeof(__u32),
	.max_entries = 10,
  .kern_access_permissions = MAP_READ_ONLY,
};

struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[100];
};

#endif // XDP_MAP_H

/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#define VLAN_MAX_DEPTH 4

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct vlanids {
	__u16 ids[VLAN_MAX_DEPTH];
};

struct vlanids* ids;

static __always_inline int proto_is_vlan(__u16 h_proto) {
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		      h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline int parse_vlanhdr(struct hdr_cursor* nh,
                                         void* data_end,
										 struct ethhdr** ethhdr,
										 struct vlanids* ids)
{
	struct ethhdr* eth = nh->pos;
	int hdrsize = sizeof(*eth);

	struct vlan_hdr* vlanh;
	__u16 h_proto;

	if (nh->pos + hdrsize > data_end)
		return -1;
	
	nh->pos += hdrsize;
	*ethhdr = eth;

	vlanh = nh->pos;
	h_proto = eth->h_proto;

	int i,
		j = 0;
	#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++)
	{
		if (!proto_is_vlan(h_proto))
			break;
		
		if (vlanh + 1 > data_end)
			break;

		h_proto = vlanh->h_vlan_encapsulated_proto;
		ids->ids[j++] = vlanh->h_vlan_TCI;

		vlanh++;
	}
	nh->pos = vlanh;
	return h_proto;
}

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr) {
	return parse_vlanhdr(nh, data_end, ethhdr, *ids);
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor* nh,
					void* data_end,
					struct ipv6hdr** ip6hdr)
{
	struct ipv6hdr* ip6h = nh->pos;

	/* Pointer-arithmetic bounds check; pointer +1 points to after end of
	 * thing being pointed to. We will be using this style in the remainder
	 * of the tutorial.
	 */
	if (ip6h + 1 > data_end)
		return -1;

	nh->pos = ip6h + 1;
	*ip6hdr = ip6h;

	return ip6h->nexthdr;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor* nh,
					  void* data_end,
					  struct icmp6hdr** icmp6hdr)
{
	struct icmp6hdr* icmp6h = nh->pos;

	if (icmp6h + 1 > data_end)
		return -1;

	nh->pos = icmp6h + 1;
	*icmp6hdr = icmp6h;

	return icmp6h->icmp6_type;
}

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	//struct ethhdr *eth;
	//struct ipv6hdr* ip6h;
	struct icmp6hdr* icmp6h;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_icmp6hdr(&nh, data_end, &icmp6h);
	if (nh_type < 0 || icmp6h == NULL) {
		goto out;
	}
	/* Assignment additions go below here */
	if (bpf_ntohs(icmp6h->icmp6_sequence) & 0x1) {
		action = XDP_PASS;
	}
	else {
		action = XDP_DROP;
	}

out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";

// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2013 - 2019 Intel Corporation. */

#include "fm10k.h"

__be16 ies_type_trans(struct sk_buff *skb)
{
	__be64 *ies;

	skb_reset_mac_header(skb);
	skb->pkt_type = PACKET_OTHERHOST;

	BUG_ON((skb_mac_header(skb) - skb->head) < sizeof(struct fm10k_ies));
	skb->mac_header -= sizeof(struct fm10k_ies);
	ies = (__be64 *)skb_mac_header(skb);

	ies[0] = cpu_to_be64(le64_to_cpu(FM10K_CB(skb)->tstamp));
	ies[1] = cpu_to_be64(le64_to_cpu(FM10K_CB(skb)->fi.ftag));

	return htons(ETH_P_IES);
}

static int ies_rcv(struct sk_buff *skb, struct net_device *dev,
		   struct packet_type *pt, struct net_device *orig_dev)
{
	dev_kfree_skb(skb);
	return 0;
}

struct packet_type ies_packet_type __read_mostly = {
	.type = htons(ETH_P_IES),
	.func = ies_rcv,
};

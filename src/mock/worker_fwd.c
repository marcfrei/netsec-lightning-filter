/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdint.h>
#include <string.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "../config.h"
#include "../configmanager.h"
#include "../lf.h"
#include "../lib/utils/packet.h"
#include "../worker.h"

static enum lf_pkt_action
handle_pkt(struct lf_worker_context *worker_context, struct rte_mbuf *m)
{
	static enum lf_pkt_action pkt_action;
	unsigned int offset;
	struct rte_ether_hdr *ether_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct lf_config_peer *peer;
	struct lf_config_pkt_mod *inbound_pkt_mod;
	struct lf_config_pkt_mod *outbound_pkt_mod;

	if (unlikely(m->data_len != m->pkt_len)) {
		LF_WORKER_LOG_DP(NOTICE,
				"Not yet implemented: buffer with multiple segments "
				"received.\n");
		return LF_PKT_UNKNOWN_DROP;
	}

	offset = 0;
	offset = lf_get_eth_hdr(m, offset, &ether_hdr);
	if (offset == 0) {
		return LF_PKT_UNKNOWN_DROP;
	}

	if (unlikely(ether_hdr->ether_type !=
				 rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))) {
		LF_WORKER_LOG_DP(NOTICE, "Unsupported packet type: must be IPv4.\n");
		return LF_PKT_UNKNOWN_DROP;
	}

	offset = lf_get_ip_hdr(m, offset, &ipv4_hdr);
	if (offset == 0) {
		return LF_PKT_UNKNOWN_DROP;
	}

	peer = lf_configmanager_worker_get_peer_from_ip(
		worker_context->config, ipv4_hdr->src_addr);
	if (unlikely((peer != NULL) && (peer->ip == ipv4_hdr->src_addr) && peer->deny)) {
		LF_WORKER_LOG_DP(DEBUG, "Dropping packet (SRC IP: " PRIIP ")\n",
			PRIIP_VAL(ipv4_hdr->src_addr));
		return LF_PKT_UNKNOWN_DROP;
	}

	inbound_pkt_mod = lf_configmanager_worker_get_inbound_pkt_mod(
		worker_context->config);
	outbound_pkt_mod = lf_configmanager_worker_get_outbound_pkt_mod(
		worker_context->config);

	if (outbound_pkt_mod->ether_option &&
		(memcmp(outbound_pkt_mod->ether, &ether_hdr->src_addr, 6) == 0)) {
		pkt_action = LF_PKT_INBOUND_FORWARD;
		(void)lf_worker_pkt_mod(m, ether_hdr, ipv4_hdr, inbound_pkt_mod);
	} else if (inbound_pkt_mod->ether_option &&
		(memcmp(inbound_pkt_mod->ether, &ether_hdr->src_addr, 6) == 0)) {
		pkt_action = LF_PKT_OUTBOUND_FORWARD;
		(void)lf_worker_pkt_mod(m, ether_hdr, ipv4_hdr, outbound_pkt_mod);
	} else {
		return LF_PKT_UNKNOWN_DROP;
	}

	LF_WORKER_LOG(DEBUG, "Forwarding packet ("
		"SRC ETHER: " RTE_ETHER_ADDR_PRT_FMT " -> DST ETHER: " RTE_ETHER_ADDR_PRT_FMT ", "
		"SRC IP: " PRIIP " -> DST IP: " PRIIP ")\n",
		RTE_ETHER_ADDR_BYTES(&ether_hdr->src_addr),
		RTE_ETHER_ADDR_BYTES(&ether_hdr->dst_addr),
		PRIIP_VAL(ipv4_hdr->src_addr),
		PRIIP_VAL(ipv4_hdr->dst_addr));

	return pkt_action;
}

void
lf_worker_handle_pkt(struct lf_worker_context *worker_context,
		struct rte_mbuf **pkt_burst, uint16_t nb_pkts,
		enum lf_pkt_action *pkt_res)
{
	int i;

	for (i = 0; i < nb_pkts; i++) {
		if (pkt_res[i] != LF_PKT_UNKNOWN) {
			/* If packet action is already determined, do not process it */
			continue;
		}

		pkt_res[i] = handle_pkt(worker_context, pkt_burst[i]);
	}
}

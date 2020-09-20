#include <linux/workqueue.h>
#include <linux/dpdk.h>
#include <linux/kdb.h>
#include <linux/kern_levels.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/sctp.h>
#include <linux/trace-helper.h>
#include <linux/kthread.h>
#include <linux/trace-helper.h>
#include <sys/ioctl.h>

#include "dev.h"
#include "arp.h"
#include "pcap_server.h"
#include "thread.h"
#include <unistd.h>

// avoid conflict between stdlib.h abs() and the kernel macro
#undef abs
// avoid re-definition of wchar_t in gcc's stddev.h
#define _WCHAR_T_DEFINED_
#include <rte_net.h>
#include <rte_skb.h>
#include <rte_ethdev.h>

// avoid include spdk header, which causes conflicts with Linux's headers
uint64_t spdk_vtophys(void *buf, uint64_t *size);

//#define DPDK_DEBUG
#define DPDK_RECEIVING 1

static int dpdk_open(struct net_device *netdev)
{
	struct netdev_dpdk *dpdk = netdev_priv(netdev);
	unsigned i;
	for (i = 0; i < dpdk->n_workers; i++) {
		napi_enable(&dpdk->poll_contexts[i].napi);
	}
	netif_tx_start_all_queues(netdev);
	//netif_carrier_on(netdev);

	return 0;
}

static int dpdk_close(struct net_device *netdev)
{
	struct netdev_dpdk *dpdk = netdev_priv(netdev);
	unsigned i;
	for (i = 0; i < dpdk->n_workers; i++) {
		napi_disable(&dpdk->poll_contexts[i].napi);
	}
	netif_tx_stop_all_queues(netdev);
	dpdk_remove(dpdk);
	return 0;
}

#ifdef DPDK_DEBUG
#include "log.h"
#else
static void dpdk_log_skb(const char *prefix, const struct sk_buff *skb)
{
}
#endif

static u16 skb_ip_proto(struct sk_buff *skb)
{
	return (ip_hdr(skb)->version == 4) ? ip_hdr(skb)->protocol :
					     ipv6_hdr(skb)->nexthdr;
}

static void tx_prep(struct rte_mbuf *rm, struct sk_buff *skb)
{
	u16 protocol;
	union {
		struct iphdr *v4;
		struct ipv6hdr *v6;
		unsigned char *hdr;
	} l3;

	union {
		struct tcphdr *tcp;
		struct udphdr *udp;
		struct gre_base_hdr *gre;
		unsigned char *hdr;
	} l4;

	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		return;
	}

	l3.hdr = skb_network_header(skb);
	l4.hdr = skb_transport_header(skb);

	protocol = skb_ip_proto(skb);

	rm->outer_l2_len = 0;
	rm->outer_l3_len = 0;
	rm->l2_len = l3.hdr - skb->data;
	rm->l3_len = l4.hdr - l3.hdr;

	if (ip_hdr(skb)->version == 4) {
		rm->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
	} else {
		rm->ol_flags |= PKT_TX_IPV6;
	}

	if (protocol == IPPROTO_TCP) {
		rm->ol_flags |= PKT_TX_TCP_CKSUM;
		rm->l4_len = l4.tcp->doff * 4;
		rm->tso_segsz = skb_shinfo(skb)->gso_size;

		if (skb_is_gso(skb)) {
			rm->ol_flags |= PKT_TX_TCP_SEG;
		}
	} else if (protocol == IPPROTO_UDP) {
		rm->l4_len = sizeof(struct udphdr);
		rm->ol_flags |= PKT_TX_UDP_CKSUM;
	} else if (protocol == IPPROTO_SCTP) {
		rm->l4_len = sizeof(struct sctphdr);

		rm->ol_flags |= PKT_TX_SCTP_CKSUM;
	} else {
		skb_checksum_help(skb);
	}
}

static void free_skb_cb(void *addr, void *skb_ptr)
{
	struct sk_buff *skb = skb_ptr;
	//struct netdev_dpdk *dpdk = netdev_priv(skb->dev);
	//BUG_ON(!skb->dev);
	//skb_queue_tail(&dpdk->sk_buff, skb);
	dev_kfree_skb_any(skb);
}

static struct rte_mbuf_ext_shared_info dpdk_shinfo = {
	.free_cb = free_skb_cb,
	.fcb_opaque = NULL,
	// prevent DPDK from freeing this
	.refcnt_atomic = { .cnt = 1 },
};

// We don't need to free frags
static void noop_cb(void *addr, void *skb_ptr)
{
}

static struct rte_mbuf_ext_shared_info dpdk_frag_shinfo = {
	.free_cb = noop_cb,
	.fcb_opaque = NULL,
	// prevent DPDK from freeing this
	.refcnt_atomic = { .cnt = 1 },
};

int dpdk_attach_skb(struct rte_mbuf *rm)
{
	size_t size = 1500; // FIXME: MTU
	struct sk_buff *skb = dev_alloc_skb(size);
	if (!skb) {
		return -ENOMEM;
	}

	rm->userdata = skb;
	rte_pktmbuf_attach_extbuf(rm, skb->data, spdk_vtophys(skb->data, NULL),
				  size, &dpdk_frag_shinfo);
	rm->data_len = size;
	rm->pkt_len = skb->len;
	rm->ol_flags |= EXT_USERDATA_ON_FREE;
	rm->buf_iova -= RTE_PKTMBUF_HEADROOM;
	return 0;
}
EXPORT_SYMBOL(dpdk_attach_skb);

static int zero_copy_skb(struct netdev_dpdk *dpdk, struct sk_buff *skb,
			 struct rte_mbuf *rm)
{
	struct rte_mbuf *seg, *previous_seg;
	void *addr;
	int i;
	size_t size = skb_is_nonlinear(skb) ? skb_headlen(skb) : skb->len;

	rm->userdata = skb;
	rte_pktmbuf_attach_extbuf(rm, skb->data, spdk_vtophys(skb->data, NULL),
				  size, &dpdk_shinfo);
	rm->data_len = size;
	rm->pkt_len = skb->len;
	rm->ol_flags |= EXT_USERDATA_ON_FREE;

	previous_seg = rm;
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		const struct skb_frag_struct *frag;
		seg = rte_pktmbuf_alloc(dpdk->txpool);
		if (!seg) {
			return -1;
		}
		previous_seg->next = seg;
		previous_seg = seg;
		rm->nb_segs += 1;

		frag = &skb_shinfo(skb)->frags[i];
		addr = lowmem_page_address(skb_frag_page(frag)) +
		       frag->page_offset;
		rte_pktmbuf_attach_extbuf(seg, addr, spdk_vtophys(addr, NULL),
					  skb_frag_size(frag),
					  &dpdk_frag_shinfo);
		seg->data_len = skb_frag_size(frag);
	}

	return 0;
}

static int copy_skb(struct netdev_dpdk *dpdk, struct sk_buff *skb,
		    struct rte_mbuf *rm)
{
	int res = 0;
	void *pkt = rte_pktmbuf_append(rm, skb->len);
	if (!pkt) {
		printk(KERN_WARNING
		       "dpdk: rte_pktmbuf_append failed: rm: %u, sbk->len: %u\n",
		       rm->pkt_len, skb->len);
		res = -1;
		goto free;
	}
	skb_copy_bits(skb, 0, pkt, skb->len);

free:
	kfree_skb(skb);
	return res;
}

extern void i40_print_queue_status(int port_id, int queue_id);

static netdev_tx_t dpdk_start_xmit(struct sk_buff *skb,
				   struct net_device *netdev)
{

	struct netdev_dpdk *dpdk = netdev_priv(netdev);
	struct rte_mbuf *rm;
	int n_tx;
	int qid = skb_get_queue_mapping(skb);

	/*  Determine which tx ring we will be placed on */

	rm = rte_pktmbuf_alloc(dpdk->txpool);
	tx_prep(rm, skb);

	//int printf(const char* f,...); printf("%s() at %s:%d\n", __func__, __FILE__, __LINE__); __asm__("int3; nop" ::: "memory");
	if (zero_copy_skb(dpdk, skb, rm) < 0) {
		printk(KERN_WARNING "dpdk: zero copy failed\n");
		return NETDEV_TX_OK;
	};

	//if (skb->len > 1000) {
	//  if (zero_copy_skb(dpdk, skb, rm) < 0) {
	//    break;
	//  };
	//} else {
	//  if (copy_skb(dpdk, skb, rm) < 0) {
	//    i40_print_queue_status(dpdk->portid, 0);

	//    int printf(const char* f,...); printf("%s() at %s:%d\n", __func__, __FILE__, __LINE__); __asm__("int3" ::: "memory"); printf("continue\n");
	//    break;
	//  };
	//  if (rm->pkt_len == 0) {
	//    int printf(const char* f,...); printf("%s() at %s:%d: %u -> %u ?\n", __func__, __FILE__, __LINE__, rm->pkt_len, skb->len);
	//    BUG_ON(true);
	//  };
	//}
	//void dump_memory_stats(void);
	//dump_memory_stats();
	dpdk_log_skb("tx", skb);

	if (unlikely(rte_eth_tx_prepare(dpdk->portid, qid, &rm, 1) != 1)) {
		printk(KERN_WARNING "dpdk: tx_prep failed\n");
		// FIXME: we cannot call rte_pktmbuf_free here since the inlined code makes our stack space exceed
		//rte_pktmbuf_free(rm);
		// TODO free skb
		return NETDEV_TX_OK;
	}
	// TODO actual use other queues
	n_tx = rte_eth_tx_burst(dpdk->portid, qid, &rm, 1);
	if (unlikely(n_tx != 1)) {
		printk(KERN_WARNING "dpdk: tx_burst failed\n");
		// FIXME: we cannot call rte_pktmbuf_free here since the inlined code makes our stack space exceed
		//rte_pktmbuf_free(rm);
		// TODO free skb
		return NETDEV_TX_OK;
	}
	//netdev_tx_sent_queue(txq, skb->len);

	return NETDEV_TX_OK;
}

static u16 dpdk_select_queue(struct net_device *ndev, struct sk_buff *skb,
				void *accel_priv,
				select_queue_fallback_t fallback)
{
	return (u16)smp_processor_id();
}

struct net_device_ops dpdk_netdev_ops = {
	.ndo_open = dpdk_open,
	.ndo_stop = dpdk_close,
	.ndo_select_queue = dpdk_select_queue,
	.ndo_start_xmit = dpdk_start_xmit,
};

void dpdk_set_mac(int portid, struct net_device *netdev)
{
	rte_eth_macaddr_get(portid, (struct ether_addr *)netdev->dev_addr);
	ether_addr_copy(netdev->perm_addr, netdev->dev_addr);
	printk(KERN_INFO "[dpdk] dpdk%d: mac address %pM\n", netdev->ifindex, netdev->dev_addr);
}

static void set_rx_hash(struct rte_mbuf *rm, struct sk_buff *skb)
{
	enum pkt_hash_types hash_type = PKT_HASH_TYPE_NONE;
	uint32_t ptype, l4_proto, l3_proto;
	struct rte_net_hdr_lens hdr_lens;

	if (unlikely((rm->ol_flags & PKT_RX_RSS_HASH) == 0))
		return;

	ptype = rte_net_get_ptype(rm, &hdr_lens, RTE_PTYPE_ALL_MASK);
	l3_proto = ptype & RTE_PTYPE_L3_MASK;
	l4_proto = ptype & RTE_PTYPE_L4_MASK;

	if (likely((l3_proto == RTE_PTYPE_L3_IPV4 ||
		    l3_proto == RTE_PTYPE_L3_IPV6) &&
		   (l4_proto == RTE_PTYPE_L4_TCP ||
		    l4_proto == RTE_PTYPE_L4_UDP ||
		    l4_proto == RTE_PTYPE_L4_SCTP))) {
		// we could also set PKT_HASH_TYPE_L3..., but nobody got time for that.
		hash_type = PKT_HASH_TYPE_L4;
	}

	skb_set_hash(skb, rm->hash.rss, hash_type);
}

static void trace_calls_print_with_queue(struct trace_data *t)
{
	struct trace_context *ctx = t->ctx;
	ticks_t diff;
	ticks_t cycles = rdtsc_e();

	if (!ctx->start_cycles) {
		ctx->start_cycles = rdtsc_s();
		return;
	}

	diff = cycles - ctx->start_cycles;

	if (diff > ctx->frequency) {
		printf("%s() at %s:%d queue (%u): calls/cycles: %lu/%lu\n",
		       ctx->function, ctx->filename, ctx->line, t->cycles,
		       ctx->counter, diff);
		ctx->start_cycles = cycles;
		ctx->counter = 0;
	}

	// FIXME: not thread-safe
	ctx->counter++;
}
static int dpdk_counter = 0;

int i40_clean_queue(int port_id, int queue_id);
static unsigned dpdk_rx_poll(struct dpdk_poll_ctx *ctx)
{
	uint16_t i;
	unsigned work_done;

	// burst receive context by rump dpdk code
	struct netdev_dpdk *dpdk = ctx->dpdk;
	struct rte_mbuf **rcv_mbuf = dpdk->rcv_mbuf;
	/* Enter critical section */
	if (test_and_set_bit(DPDK_RECEIVING, &dpdk->state)) {
		return 0;
	}

	//for (i = 0; i < 2; i++) {
	//	i40_clean_queue(ctx->dpdk->portid, i);
	//}

	while (1) {
		uint16_t nb_rx = rte_eth_rx_burst(dpdk->portid,
										  ctx->queue,
										  rcv_mbuf,
										  MAX_PKT_BURST);

		if (nb_rx == 0) {
			napi_gro_flush(&ctx->napi, false);
			clear_bit(DPDK_RECEIVING, &dpdk->state);
			return work_done;
		}

		for (i = 0; i < nb_rx; i++) {
			struct rte_mbuf *rm = rcv_mbuf[i];
			uint32_t len = rte_pktmbuf_pkt_len(rm);
			struct sk_buff *skb = rm->userdata;

			skb->len = len;
			work_done += len;
			skb_set_tail_pointer(skb, skb->len);
			skb->dev = dpdk->dev;
			skb->protocol = eth_type_trans(skb, dpdk->dev);

			skb->ip_summed = CHECKSUM_UNNECESSARY;

			// This currently makes performance worse...
			//set_rx_hash(m, skb);

			dpdk_log_skb("rx", skb);
			if (!skb) {
				int printf(const char* f,...); printf("%s() at %s:%d\n", __func__, __FILE__, __LINE__); __asm__("int3; nop" ::: "memory");
			}
			napi_gro_receive(&ctx->napi, skb);

			rte_pktmbuf_free(rm);
		}

		//if (dpdk_counter % 10000 == 0) {
		//	int printf(const char* f,...); printf("\033[31;1m%s() at %s:%d: queue %u\033[0m\n", __func__, __FILE__, __LINE__, ctx->queue);
		//}
	}
}

int dpdk_napi(struct napi_struct *napi, const int budget)
{
	unsigned work_done;
	struct dpdk_poll_ctx *ctx = container_of(napi, struct dpdk_poll_ctx, napi);
	return dpdk_rx_poll(ctx);
}

void dpdk_poll_worker(struct work_struct *work)
{
	struct dpdk_poll_ctx *ctx = container_of(work, struct dpdk_poll_ctx, work);
	dpdk_rx_poll(ctx);
	queue_delayed_work_on(smp_processor_id(), system_highpri_wq, &ctx->work, msecs_to_jiffies(100));
	dpdk_counter++;
	if (dpdk_counter % 1000 == 0) {
		int printf(const char* f,...); printf("\033[31;1m%s() at %s:%d\033[0m\n", __func__, __FILE__, __LINE__);
		//void i40_clean_queue(int port_id, int queue_id);
		//i40_clean_queue(ctx->dpdk->portid, ctx->queue);
		i40_print_queue_status(ctx->dpdk->portid, ctx->queue);
	}

}

int dpdk_num_rx_queues(struct netdev_dpdk *dev)
{
	struct rte_eth_dev_info dev_info;

	rte_eth_dev_info_get(dev->portid, &dev_info);
	return dev_info.nb_rx_queues;
};

int i40e_attach_skb_to_rx_queues(struct rte_eth_dev *dev);
void dpdk_initialize_skb_function(void)
{
	int portid;
	rte_attach_skb = dpdk_attach_skb;
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		struct rte_eth_dev *device = &rte_eth_devices[portid];
		if (!device->device) {
			continue;
		}
		i40e_attach_skb_to_rx_queues(device);
	}
}

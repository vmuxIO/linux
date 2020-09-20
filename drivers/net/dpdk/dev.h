#ifndef _DPDK_DEV_H_
#define _DPDK_DEV_H_

#include <uapi/linux/dpdk.h>
#include <linux/netdevice.h>

// avoid conflict between stdlib.h abs() and the kernel macro
#undef abs
// avoid re-definition of wchar_t in gcc's stddev.h
#define _WCHAR_T_DEFINED_
#include <rte_mbuf.h>

extern struct list_head dpdk_devs;

#define MAX_PKT_BURST 8
struct dpdk_poll_ctx {
	struct delayed_work	work;
	int queue;
	struct netdev_dpdk *dpdk;
	struct napi_struct napi;
};

struct netdev_dpdk {
	struct net_device *dev;
	struct dpdk_poll_ctx *poll_contexts;
	unsigned n_workers;
	int stop_polling;

	int portid;
	unsigned long state;
	struct rte_mbuf *rcv_mbuf[MAX_PKT_BURST];

	struct rte_mempool *txpool; /* ring buffer pool */
};

int dpdk_add(struct dpdk_dev *dev);
void dpdk_remove(struct netdev_dpdk *dev);

#endif // _DPDK_DEV_H_

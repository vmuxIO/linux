#ifndef _DPDK_NET_H_
#define _DPDK_NET_H_

#include <linux/interrupt.h>
#include "dev.h"

extern struct net_device_ops dpdk_netdev_ops;

void dpdk_set_mac(int portid, struct net_device *netdev);
void dpdk_initialize_skb_function(void);
int dpdk_napi(struct napi_struct *napi, const int budget);
void dpdk_poll_worker(struct work_struct *work);
int dpdk_num_rx_queues(struct netdev_dpdk *dev);

#endif

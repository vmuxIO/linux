#include "dev.h"

#include "linux/slab.h"
#include "linux/smp.h"
#include "linux/workqueue.h"
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/kthread.h>

#include "net.h"
#include "thread.h"

int dpdk_add(struct dpdk_dev *dev)
{
	unsigned i;
	struct net_device *netdev;
	struct netdev_dpdk *dpdk;
	int ret;

	netdev = alloc_etherdev_mq(sizeof(*dpdk), num_online_cpus());
	if (!netdev)
		return -ENOMEM;

	dpdk = (struct netdev_dpdk *)netdev_priv(netdev);
	dpdk->dev = netdev;
	dpdk->portid = dev->portid;
	dpdk->txpool = dev->txpool;

	strcpy(netdev->name, "dpdk%d");

	dpdk_set_mac(dev->portid, netdev);

	enum { FEATURES = NETIF_F_GRO | NETIF_F_HIGHDMA | NETIF_F_RXCSUM |
			  NETIF_F_HW_CSUM | NETIF_F_SG | NETIF_F_TSO |
			  NETIF_F_TSO_ECN | NETIF_F_TSO6 | 0 };

	netdev->features |= FEATURES;
	netdev->hw_features |= FEATURES;
	netdev->hw_enc_features |= FEATURES;

	netdev->netdev_ops = &dpdk_netdev_ops;

	ret = register_netdev(netdev);

	if (ret) {
		printk(KERN_WARNING "failed to register dpdk device: %d\n",
		       ret);
		goto free_netdev;
	}

	dpdk->n_workers = dpdk_num_rx_queues(dpdk);
	dpdk->poll_contexts = kmalloc_array(dpdk->n_workers, sizeof(*dpdk->poll_contexts),
				      __GFP_ZERO);
	if (!dpdk->poll_contexts) {
		goto unregister_netdev;
	}
	for (i = 0; i < dpdk->n_workers; i++) {
		struct dpdk_poll_ctx *ctx = &dpdk->poll_contexts[i];
		ctx->queue = i;
		ctx->dpdk = dpdk;
		netif_napi_add(netdev, &ctx->napi, dpdk_napi, NAPI_POLL_WEIGHT);
		INIT_DELAYED_WORK(&ctx->work, dpdk_poll_worker);
		queue_delayed_work_on(i, system_highpri_wq, &ctx->work, msecs_to_jiffies(10));
	}

	return netdev->ifindex;

unregister_netdev:
	unregister_netdev(netdev);
free_netdev:
	free_netdev(netdev);
	return ret;
}

void dpdk_remove(struct netdev_dpdk *dev)
{
	unsigned i;
	unregister_netdev(dev->dev);
	free_netdev(dev->dev);

	for (i = 0; i < dev->n_workers; i++) {
		netif_napi_del(&dev->poll_contexts[i].napi);
		cancel_delayed_work_sync(&dev->poll_contexts[i].work);
	}
	kfree(dev->poll_contexts);
}

#ifndef _DPDK_LOG_H_
#define _DPDK_LOG_H_

#include <linux/skbuff.h>

void dpdk_log_skb(const char *prefix, const struct sk_buff *skb);

#endif // _DPDK_LOG_H_

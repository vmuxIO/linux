#include "log.h"

#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <linux/spinlock.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <linux/in6.h>

struct tcpudphdr {
    __be16 src;
    __be16 dst;
};

struct arppayload {
    unsigned char mac_src[ETH_ALEN];
    unsigned char ip_src[4];
    unsigned char mac_dst[ETH_ALEN];
    unsigned char ip_dst[4];
};

static void print_ports(const struct sk_buff *skb, uint8_t protocol, int offset) {
    if (protocol == IPPROTO_TCP ||
        protocol == IPPROTO_UDP ||
        protocol == IPPROTO_UDPLITE ||
        protocol == IPPROTO_SCTP ||
        protocol == IPPROTO_DCCP) {
        const struct tcpudphdr *pptr;
        struct tcpudphdr _ports;

        pptr = skb_header_pointer(skb, offset,
                                  sizeof(_ports), &_ports);
        if (pptr == NULL) {
            printk(" INCOMPLETE TCP/UDP header");
            return;
        }
        printk(" SPT=%u DPT=%u", ntohs(pptr->src), ntohs(pptr->dst));
    }
}

static DEFINE_SPINLOCK(dpdk_log_lock);

void dpdk_log_skb(const char *prefix, const struct sk_buff *skb) {
    spin_lock_bh(&dpdk_log_lock);

    printk(KERN_INFO "%s MAC source = %pM MAC dest = %pM proto = 0x%04x",
           prefix, eth_hdr(skb)->h_source, eth_hdr(skb)->h_dest,
           ntohs(eth_hdr(skb)->h_proto));

    if (eth_hdr(skb)->h_proto == htons(ETH_P_IP)) {
        const struct iphdr *ih;
        struct iphdr _iph;

        ih = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
        if (ih == NULL) {
            printk(" INCOMPLETE IP header");
            goto out;
        }
        printk(" IP SRC=%pI4 IP DST=%pI4, IP tos=0x%02X, IP proto=%d",
               &ih->saddr, &ih->daddr, ih->tos, ih->protocol);
        print_ports(skb, ih->protocol, ih->ihl*4);
        goto out;
    }

    if (eth_hdr(skb)->h_proto == htons(ETH_P_IPV6)) {
        const struct ipv6hdr *ih;
        struct ipv6hdr _iph;
        uint8_t nexthdr;
        __be16 frag_off;
        int offset_ph;

        ih = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
        if (ih == NULL) {
            printk(" INCOMPLETE IPv6 header");
            goto out;
        }
        printk(" IPv6 SRC=%pI6 IPv6 DST=%pI6, IPv6 priority=0x%01X, Next Header=%d",
               &ih->saddr, &ih->daddr, ih->priority, ih->nexthdr);
        nexthdr = ih->nexthdr;
        offset_ph = ipv6_skip_exthdr(skb, sizeof(_iph), &nexthdr, &frag_off);
        if (offset_ph == -1)
            goto out;
        print_ports(skb, nexthdr, offset_ph);
        goto out;
    }

    if (((eth_hdr(skb)->h_proto == htons(ETH_P_ARP)) ||
         (eth_hdr(skb)->h_proto == htons(ETH_P_RARP)))) {
        const struct arphdr *ah;
        struct arphdr _arph;

        ah = skb_header_pointer(skb, 0, sizeof(_arph), &_arph);
        if (ah == NULL) {
            printk(" INCOMPLETE ARP header");
            goto out;
        }
        printk(" ARP HTYPE=%d, PTYPE=0x%04x, OPCODE=%d",
               ntohs(ah->ar_hrd), ntohs(ah->ar_pro),
               ntohs(ah->ar_op));

        /* If it's for Ethernet and the lengths are OK,
         * then log the ARP payload */
        if (ah->ar_hrd == htons(1) &&
            ah->ar_hln == ETH_ALEN &&
            ah->ar_pln == sizeof(__be32)) {
            const struct arppayload *ap;
            struct arppayload _arpp;

             ap = skb_header_pointer(skb, sizeof(_arph),
                         sizeof(_arpp), &_arpp);
             if (ap == NULL) {
                 printk(" INCOMPLETE ARP payload");
                 goto out;
             }
             printk(" ARP MAC SRC=%pM ARP IP SRC=%pI4 ARP MAC DST=%pM ARP IP DST=%pI4",
                     ap->mac_src, ap->ip_src, ap->mac_dst, ap->ip_dst);
         }
     }
 out:
    printk("\n");
    spin_unlock_bh(&dpdk_log_lock);
}

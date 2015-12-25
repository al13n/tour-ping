#ifndef __ARP_H
#define __ARP_H

#include <assert.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include "unp.h"
#include "hw_addrs.h"

#define PROTOCOL_NUMBER 1537
#define ARP_FILE    "/tmp/apoddar_arp"
#define ARP_CACHE_SIZE 100

typedef struct {
    struct in_addr ipAddr;
    char hwAddr[IF_HADDR];
    int sll_ifindex;
    int sll_hatype;
    int connfd;
    int valid;
} ARPCacheEntry;

typedef enum{
	ARP_REPLY,
	ARP_REQ
}msg_type;

typedef struct {
	msg_type type;
	uint16_t protocol;

    uint16_t id;
    uint16_t htype;
    uint8_t hlen;
    uint8_t plen;

	struct in_addr sender_ip_addr;
	char sender_ethernet_addr[6];
	struct in_addr dest_ip_addr;	
	char dest_ethernet_addr[6];
}arp_packet;

typedef struct {
    uint8_t destMAC[IF_HADDR];
    uint8_t srcMAC[IF_HADDR];
    uint16_t protocol;
    arp_packet ARP;
} EthernetFrame;

#endif
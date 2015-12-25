#ifndef __API_H
#define __API_H

#include <assert.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include "unp.h"
#include "hw_addrs.h"



typedef struct{
	struct in_addr ip;
	int ifindex;
	int hatype;
}api_packet;

typedef struct {
    int      sll_ifindex;    /* Interface number */
    uint16_t sll_hatype;     /* Hardware type */
    uint8_t  sll_halen;      /* Length of address */
    uint8_t  sll_addr[8];    /* Physical layer address */
} hwaddr;

int areq(struct sockaddr *IPaddr, socklen_t sockaddrlen, hwaddr *HWaddr);

uint16_t in_cksum(uint16_t *addr, int len);

#endif
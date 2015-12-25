#ifndef _TOUR_TEST_H
#define _TOUR_TEST_H

#include <assert.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <assert.h>
#include <setjmp.h>
#include <sys/socket.h>
#include "unp.h"
//#include "hw_addrs.h"

#define MAXHOPS 100
#define IPPROTO_TOUR 167
#define UNIQ_ID 167
#define TTL_OUT 1
#define MULTICAST_IP   "234.245.210.120"
#define MULTICAST_PORT 9854
#define MAX_BUF        1000

typedef struct{
    	int currentPos;
    	int total_nodes;
    	struct in_addr tourList[MAXHOPS];
    	struct in_addr multicastIP;
    	int multicastPort;
}Data;

typedef struct {
    struct ip header;
    Data data;
} Packet;


typedef struct{
	struct ip ipHeader;
	struct icmp icmpHeader;
}__attribute__((packed)) pgPacketHeader;

typedef struct {
	char destEth[6];
	char srcEth[6];
	uint16_t protocol;
	pgPacketHeader pgHeader;
}__attribute__((packed)) pgPacket;


void send_pgPacket(int pf_fd, struct in_addr srcIP, struct in_addr destIP, char *host_eth);

void proc_v4(int fd);

#endif
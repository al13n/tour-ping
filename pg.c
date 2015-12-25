#include "tour-test.h"
#include "api.h"

static pg_seq_no = 1;

char* ethAddrNtoP(char *nMAC) {
    static char pMAC[25];
    char buf[10];
    int i;

    pMAC[0] = '\0';
    for (i = 0; i < IF_HADDR; i++) {
        sprintf(buf, "%.2x%s", nMAC[i] & 0xff , i == 5 ? "" : ":");
        strcat(pMAC, buf);
    }
    return pMAC;
}

void send_pgPacket(int pf_fd, struct in_addr srcIP, struct in_addr destIP, char *host_eth){
	
	pgPacket packet;
	memset(&packet,  '\0', sizeof(pgPacket));
	hwaddr *HWaddr;
	HWaddr = (hwaddr* )malloc(sizeof(hwaddr));
	HWaddr->sll_halen = ETH_ALEN;
	HWaddr->sll_hatype = ARPHRD_ETHER;
	HWaddr->sll_ifindex = 2;

	struct sockaddr_in *IPaddr;
	IPaddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	IPaddr->sin_family = AF_INET;
	IPaddr->sin_port = 0;
	IPaddr->sin_addr.s_addr = destIP.s_addr;

	int sock_len = sizeof(struct sockaddr);
	areq((struct sockaddr *)IPaddr, sock_len, HWaddr);

	printf("Recv from AREQ: %s\n", ethAddrNtoP(HWaddr->sll_addr));

	memcpy(packet.destEth, HWaddr->sll_addr, IF_HADDR);
	memcpy(packet.srcEth, host_eth, IF_HADDR);


	packet.protocol = htons(ETH_P_IP);

	struct icmp * ic_hdr;
	ic_hdr = &(packet.pgHeader.icmpHeader);
	ic_hdr->icmp_type = ICMP_ECHO;
	ic_hdr->icmp_code = 0;
	ic_hdr->icmp_id = htons(UNIQ_ID);
	ic_hdr->icmp_seq = htons(pg_seq_no++);

	//getimeofday
	Gettimeofday((struct timeval *) ic_hdr->icmp_data, NULL);
	ic_hdr->icmp_cksum = 0;
	ic_hdr->icmp_cksum = in_cksum((uint16_t *)ic_hdr, sizeof(struct icmp));



	packet.pgHeader.ipHeader.ip_hl = sizeof(struct ip) >> 2;
	packet.pgHeader.ipHeader.ip_v = IPVERSION;
	packet.pgHeader.ipHeader.ip_tos = 0;
	packet.pgHeader.ipHeader.ip_len = htons(sizeof(pgPacketHeader));
	packet.pgHeader.ipHeader.ip_id = htons(UNIQ_ID);
	packet.pgHeader.ipHeader.ip_off = 0;
	packet.pgHeader.ipHeader.ip_ttl = 64;
	packet.pgHeader.ipHeader.ip_p = IPPROTO_ICMP;
	packet.pgHeader.ipHeader.ip_src.s_addr = srcIP.s_addr;
	packet.pgHeader.ipHeader.ip_dst.s_addr = destIP.s_addr;
	packet.pgHeader.ipHeader.ip_sum = in_cksum((uint16_t *)&packet.pgHeader.ipHeader, sizeof(struct ip));

	

	struct sockaddr_ll sockAddr;
	bzero(&sockAddr, sizeof(struct sockaddr_ll));
	sockAddr.sll_family = PF_PACKET;
	sockAddr.sll_halen = ETH_ALEN;
	sockAddr.sll_ifindex = 2;
	memcpy(sockAddr.sll_addr, HWaddr->sll_addr, IF_HADDR);

	if( sendto(pf_fd, &packet, sizeof(packet), 0, (struct sockaddr *)&sockAddr, sizeof(sockAddr)) < 0 ){
		perror("ping packet: SENDTO error");
	}


}

void
tv_sub(struct timeval *out, struct timeval *in)
{
        if ( (out->tv_usec -= in->tv_usec) < 0) {       /* out -= in */
                --out->tv_sec;
                out->tv_usec += 1000000;
        }
        out->tv_sec -= in->tv_sec;
}

void
proc_v4(int fd)
{	
	pgPacketHeader packet;
	int				hlen1, icmplen;
	double			rtt;
	struct ip		*ip;
	struct icmp		*icmp;
	struct timeval	*tvsend;
	struct timeval  *tvrecv = (struct timeval *)malloc(sizeof(struct timeval));


    int rcv = recvfrom(fd,&packet,sizeof(packet),0,NULL,NULL);

    ip = &(packet.ipHeader);
    icmp = &(packet.icmpHeader);

	hlen1 = ip->ip_hl << 2;
	//if (ip->ip_p != IPPROTO_ICMP)
	//	return;	

	//if (icmp->icmp_type == ICMP_ECHOREPLY) {
		tvsend = (struct timeval *) icmp->icmp_data;
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;
		char ipsrc[INET_ADDRSTRLEN];
		printf("PING %d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
				icmplen, inet_ntop(AF_INET,&(ip->ip_src),ipsrc,INET_ADDRSTRLEN),
				icmp->icmp_seq, ip->ip_ttl, rtt);

	//} 
}
#include <assert.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include "unp.h"
//#include "hw_addrs.h"
#include "tour-test.h"
#include "api.h"

char hostname[10];
struct hostent *hostvm;
char host_ether[6];
struct in_addr hostip;
int rtSD,mSD,pgReqSD, pgRepSD;
struct in_addr ipList[MAXHOPS];
int mPort;
struct in_addr mIP;
int inGroup = 0;
int isLastNodeOfTour = 0;
sendPings sendPingTo[MAXHOPS];


void get_hw_addr(char*);

int shouldPing(){
    int i;
    for(i = 0; i < MAXHOPS; i++){
        if(sendPingTo[i].valid){
            return 1;
        }
    }
    return 0;
}

void setMultiCast() {
    if(!inGroup){
        int status;
        struct sockaddr_in saddr;
        struct ip_mreq imreq;

        unsigned char ttl = 1;
        unsigned char one = 1;

        // set content of struct saddr and imreq to zero
        memset(&saddr, 0, sizeof(struct sockaddr_in));
        memset(&imreq, 0, sizeof(struct ip_mreq));

        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(mPort);
        saddr.sin_addr.s_addr = mIP.s_addr; // bind socket to any interface

        Bind(mSD, (struct sockaddr *)&saddr, sizeof(saddr));

        setsockopt(mSD, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(unsigned char));

        // send multicast traffic to myself too
        setsockopt(mSD, IPPROTO_IP, IP_MULTICAST_LOOP, &one, sizeof(unsigned char));

        /* use setsockopt() to request that the kernel join a multicast group */
        saddr.sin_addr = mIP; // bind socket to any interface

        imreq.imr_multiaddr = mIP;
        imreq.imr_interface = hostip; // use DEFAULT interface

        // JOIN multicast group on default interface
        status = setsockopt(mSD, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
                (const void *)&imreq, sizeof(struct ip_mreq));
        inGroup = 1;
    }
    return ;
} 

void fillIPHeader(Packet* packet, struct in_addr destip, int numBytes) {
    packet->header.ip_hl  = sizeof(struct ip) >> 2;
    packet->header.ip_v   = IPVERSION;
    packet->header.ip_tos = 0;
    packet->header.ip_len = htons(numBytes);
    packet->header.ip_id  = htons(UNIQ_ID);
    packet->header.ip_off = 0;
    packet->header.ip_ttl = TTL_OUT;
    packet->header.ip_p   = IPPROTO_TOUR;
}

void createPacket(Packet* packet, int total_nodes){
    printf("Create tour packet: \n");
    bzero(packet, sizeof(Packet));
    packet->data.total_nodes = total_nodes;
    memcpy(packet->data.tourList, ipList, (sizeof(struct in_addr) * MAXHOPS));
    packet->data.currentPos = 0;
    packet->data.multicastIP   = mIP;
    packet->data.multicastPort = mPort;
    printf("Total nodes in tour: %d\n", total_nodes);
    fillIPHeader(packet, packet->data.tourList[packet->data.currentPos + 1], sizeof(Packet));
}

void updateAndSendPacket(Packet* packet){
    printf("Node %s :Updating and sending tour packet forward\n", hostname);
	packet->data.currentPos++;
	struct sockaddr_in tourSockAddr;
	bzero(&tourSockAddr, sizeof(tourSockAddr));
    tourSockAddr.sin_family = AF_INET;
    tourSockAddr.sin_addr = packet->data.tourList[packet->data.currentPos];
    //update header
	packet->header.ip_src = hostip;
    packet->header.ip_dst = packet->data.tourList[packet->data.currentPos];
    packet->header.ip_sum = htons(in_cksum((uint16_t *)packet, sizeof(Packet)));
	Sendto(rtSD, packet, sizeof(Packet), 0, (SA*) &tourSockAddr, sizeof(tourSockAddr));
}

static void handleMulticast() {
    char buf[MAX_BUF];
    struct sockaddr_in addr;
    fd_set fdSet;
    struct timeval timeout;
    int maxfd;
    int n;

    n = Recvfrom(mSD, buf, MAX_BUF, 0, NULL, NULL);
    buf[n] = '\0';
    printf("Node %s. Received Multicast message from group\n", hostname);
    printf("Node %s. Received: %s\n", hostname, buf);

    /* set up destination address */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr = mIP;
    addr.sin_port = htons(mPort);

    sprintf(buf, "<<<<< Node %s. I am a member of the group. >>>>>",hostname);
    printf("\nNode %s => Sending to multicast group\n\n", hostname);
    printf("\nNode %s => Sending: %s\n\n", hostname, buf);

    Sendto(mSD, buf, sizeof(buf), 0, (SA *) &addr, sizeof(addr));


    while (1) {
        FD_ZERO(&fdSet);
        FD_SET(mSD, &fdSet);
        maxfd = mSD + 1;
        timeout.tv_sec  = 5;
        timeout.tv_usec = 0;

        n = Select(maxfd, &fdSet, NULL, NULL, &timeout);

        if (n == 0) {
            printf("-----------------Terminating Tour Application.--------------------\n");
            exit(0);
        }

        if (FD_ISSET(mSD, &fdSet)) {
            n = Recvfrom(mSD, buf, MAX_BUF, 0, NULL, NULL);
            buf[n] = '\0';
            printf("Node %s. Received: %s\n", hostname, buf);
        }
    }
}

void sendToMulticastGroup() {
    char buf[MAX_BUF];
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr = mIP;
    addr.sin_port = htons(mPort);

    sprintf(buf, "<<<<< This is node %s. Tour has ended. Group members please identify yourselves. >>>>>",
            hostname);
    printf("Node %s. Sending: %s\n", hostname, buf);
    Sendto(mSD, (void *)buf, MAX_BUF, 0, (SA *) &addr, sizeof(addr));
}


void createSockets() {
	int iOptVal;
    printf("\nCreating 4 sockets:\n");
    if((rtSD   = socket(AF_INET, SOCK_RAW, IPPROTO_TOUR)) < 0){
    	err_quit("rtSD: socket error");
    }
    else{
    	if (setsockopt(rtSD, IPPROTO_IP, IP_HDRINCL, &iOptVal, sizeof(iOptVal)) < 0){
    		err_quit("rtSD: setsockopt error");
    	}
        printf("Route Socket created\n");
    }

    if((mSD   = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
    	err_quit("mSD: socket error");
    }
    else{
    	if (setsockopt(mSD, SOL_SOCKET, SO_REUSEADDR, &iOptVal, sizeof(iOptVal)) < 0){
    		err_quit("mSD: setsockopt error");
    	}
        printf("Multicast Socket created\n");
    }
    if((pgReqSD   = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0){
    	err_quit("pgReqSD: socket error");
    }
    else{
        printf("Ping Request Socket created\n");
    }

    if((pgRepSD = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
    	err_quit("pgRepSD: socket error");
    }
    else{
        printf("Ping Reply Socket created\n");
    }

    printf("---------------------------------------------------\n");
}


struct in_addr getInaddr(char *addr){
	char ip[INET_ADDRSTRLEN];
	struct in_addr ipAddr;
	inet_ntop(AF_INET, addr, ip, INET_ADDRSTRLEN);
	inet_pton(AF_INET, ip, &ipAddr);
	return ipAddr;
}

void initMulticast(struct in_addr multicastIP, int port){
    mIP = multicastIP;
    mPort = port;
}

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

/* ALl the initialisation method calls here */
void init(){
    struct in_addr ip;
	gethostname(hostname, 10);
	hostvm = gethostbyname(hostname);
	hostip = getInaddr(hostvm->h_addr);
    get_hw_addr(host_ether);
	ipList[0] = hostip;
    printf("Hostname: %s\n", hostname);
    printf("Host Ethernet Addr: %s", ethAddrNtoP(host_ether));
	createSockets();
    inet_pton(AF_INET, MULTICAST_IP, &ip);
    initMulticast(ip, MULTICAST_PORT);
}




int main(int argc, char* argv[]){
	int i;
	struct hostent *vm = NULL;
	struct in_addr ip[INET_ADDRSTRLEN];
	Packet packet;
	fd_set fdSet;
    int maxfd;

	init();
    //areq();

	if(argc > 1){
		for(i=1; i < argc; i++){
			vm = gethostbyname(argv[i]);
			ipList[i] = getInaddr(vm->h_addr);
		}
        setMultiCast();
		createPacket(&packet, argc);
		updateAndSendPacket(&packet);
		bzero(&packet, sizeof(Packet));
	}

    int lastNodePings = 5;
    while (1) {
    	FD_ZERO(&fdSet);
    	FD_SET(rtSD, &fdSet);
    	FD_SET(pgRepSD, &fdSet);
        FD_SET(mSD, &fdSet);
            
        struct timeval timeout;
        timeout.tv_sec  = 5;
        timeout.tv_usec = 0;

        maxfd = max(rtSD, pgRepSD);
        maxfd = max(maxfd, mSD);
        int n = Select(maxfd + 1, &fdSet, NULL, NULL, shouldPing() ? &timeout: NULL);


        if( n == 0){
            printf("Ping timed out: Send new ping request\n");
            if(isLastNodeOfTour){
                if(lastNodePings == 0){
                    sendToMulticastGroup();
                }
                lastNodePings--;
            }
            int i;
            for(i = 0; i < MAXHOPS; i++){
                if(sendPingTo[i].valid)
                    send_pgPacket(pgReqSD, hostip, sendPingTo[i].ip, host_ether); 
            }
        }

        if(FD_ISSET(pgRepSD, &fdSet)){
            printf("\nReceived ping packet: \n");
            proc_v4(pgRepSD);
        }


        // Received IP Packet on tour rt socket
        if (FD_ISSET(rtSD, &fdSet)) {
        	if(Recvfrom(rtSD, &packet, sizeof(Packet), 0, NULL, NULL) < 0){
        		err_msg("rtSD:Recvfrom error");
        	}
        	else{
    			if (ntohs(packet.header.ip_id) != UNIQ_ID) {
        			err_msg("IP Packet with Unknown Identification Number received");
        			return 0;
    			}

    			struct in_addr ipAddr = packet.header.ip_src;
    			vm = gethostbyaddr(&ipAddr, sizeof(ipAddr), AF_INET);

    			time_t ticks = time(NULL);
    			char strbuf[MAXLINE];
    			char ip[INET_ADDRSTRLEN];
    			inet_ntop(AF_INET, vm->h_addr, ip, INET_ADDRSTRLEN);
        		snprintf(strbuf, sizeof(strbuf), "%.24s", ctime(&ticks));
    			printf("[%s] received source routing packet from %s\n", strbuf, vm->h_name);

                initMulticast(packet.data.multicastIP, packet.data.multicastPort);
                setMultiCast();
                int i;
                for(i = 0; i < MAXHOPS; i++){
                    if(!sendPingTo[i].valid){
                        sendPingTo[i].valid = 1;
                        sendPingTo[i].ip = packet.data.tourList[packet.data.currentPos-1];
                        break;
                    }
                }

                //send_pgPacket(int pf_fd, struct in_addr srcIP, struct in_addr destIP, char *host_eth);
                
                send_pgPacket(pgReqSD, hostip, packet.data.tourList[packet.data.currentPos-1], host_ether); 
                
                
    			if(packet.data.currentPos == (packet.data.total_nodes-1)){
    				printf("<<<<< This is %s. Tour has ended. Group members please identify yourselves. >>>>>\n", hostname);
    			    isLastNodeOfTour = 1;
                }
    			else{
    				updateAndSendPacket(&packet);
    			}
                
        	}
        }

        if (FD_ISSET(mSD, &fdSet)) {
            printf("\n");
            handleMulticast();
        }

       

    }



	return 0;
}




void get_hw_addr(char *hw_addr)
{
        struct hwa_info *hwa, *hwahead;
        struct sockaddr *sa;
        char   *ptr;
        int    i, prflag;

        printf("\n");

        for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next) {

            if (strcmp(hwa->if_name,"eth0")==0) {
                memcpy(hw_addr,hwa->if_haddr,6);
                printf("%s :%s", hwa->if_name, ((hwa->ip_alias) == IP_ALIAS) ? " (alias)\n" : "\n");

                if ( (sa = hwa->ip_addr) != NULL)
                        printf("         IP addr = %s\n", Sock_ntop_host(sa, sizeof(*sa)));

                prflag = 0;
                i = 0;
                do {
                        if (hwa->if_haddr[i] != '\0') {
                                prflag = 1;
                                break;
                        }
                } while (++i < IF_HADDR);

                if (prflag) {
                        printf("         HW addr = ");
                        ptr = hwa->if_haddr;
                        i = IF_HADDR;
                        do {
                                printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
                        } while (--i > 0);
                }

                printf("\n         interface index = %d\n\n", hwa->if_index);
            }
        }

        free_hwa_info(hwahead);
    //    exit(0);
}

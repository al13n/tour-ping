#include "arp.h"
#include "api.h"

char hostname[10];
struct hostent *hostvm;
struct in_addr hostip;
char host_ether[6];
int pfSockFd, unSockFd;
//char filePath[1024];

ARPCacheEntry cache_entries[ARP_CACHE_SIZE];

void get_hw_addr(char*);

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

char* getIPStrByIPAddr(struct in_addr ipAddr) {
    struct hostent *hostInfo = NULL;
    static char ipStr[INET_ADDRSTRLEN];

    if (inet_ntop(AF_INET, (void*) &ipAddr, ipStr, INET_ADDRSTRLEN))
        return ipStr;
    else
        return NULL;
}

void displayEthernetPacket(EthernetFrame *frame){
	printf ("Ethernet frame header =>\n");
    printf ("Destination MAC: %s\n", ethAddrNtoP(frame->destMAC));
    printf ("Source MAC: %s\n", ethAddrNtoP(frame->srcMAC));
    printf("Protocol Number: %x\n", frame->protocol);
    /*
    ARPPacket *packet = &frame->ARP;
    printf ("ARP header =>\n");
    printf("Ident Num: %x\t", packet->id);
    printf("HAType: %d\t", packet->htype);
    printf("Protocol Num: %x\n", packet->protocol);
    printf("HALen: %d\t", packet->hlen);
    printf("ProtSize: %d\t", packet->plen);
    printf("SrcIP: %s\t", getIPStrByIPAddr(packet->srcIP));
    printf("DestIP: %s\n", getIPStrByIPAddr(packet->destIP));
    printf("SrcMAC: %s\t", ethAddrNtoP(packet->srcMAC));
    printf("DestMAC: %s\n", ethAddrNtoP(packet->destMAC));
    */
}

int search_cache(struct in_addr ip, char* hw_addr){
    printf("\nSearch cache for ip string: %s\n", getIPStrByIPAddr(ip));
	int i;
	for(i = 0; i < ARP_CACHE_SIZE; i++){
		if(cache_entries[i].valid){
			if(ip.s_addr == cache_entries[i].ipAddr.s_addr){
				memcpy(hw_addr, &cache_entries[i].hwAddr, IF_HADDR);
				return i;
			}
		}
	}
	return -1;
}

//Return fd on update
//TODO: forceUpdate
int update_cache(struct in_addr ipAddr, char *hw_addr, int ifindex, int hatype, int connfd, int forceUpdate){
	printf("\nARP: Update cache\n");
    char hw[6];
	int ret = search_cache(ipAddr, hw);
	int i;
	
	if(ret == -1){
		for(i = 0; i < ARP_CACHE_SIZE; i++){
			if(!cache_entries[i].valid){
				ret = i;
				break;
			}
		}
	}

    cache_entries[ret].ipAddr = ipAddr;
    if(hw_addr != NULL)
    	memcpy(cache_entries[ret].hwAddr, hw_addr, 6);

    cache_entries[ret].sll_ifindex = ifindex;
    cache_entries[ret].sll_hatype = hatype;
    
    if(connfd != -1)
    	cache_entries[ret].connfd = connfd;

    cache_entries[ret].valid = 1;

	return cache_entries[ret].connfd;
}

void createSockets(){
	pfSockFd = Socket(PF_PACKET, SOCK_RAW, htons(PROTOCOL_NUMBER));
	struct sockaddr_un sockAddr;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      
    unSockFd = Socket(AF_LOCAL, SOCK_STREAM, 0);

    bzero(&sockAddr, sizeof(sockAddr));
    memset(&sockAddr, '\0', sizeof(struct sockaddr_un));
    sockAddr.sun_family = AF_LOCAL;
    strcpy(sockAddr.sun_path, ARP_FILE);

    unlink(ARP_FILE);
    int b = bind(unSockFd, (struct sockaddr *) &sockAddr, sizeof(sockAddr));
    if(b < 0){
    	perror("Bind error\n");
    }
    int l = listen(unSockFd, 10);
    if(l < 0){
    	perror("listen error");
    }
    else{
        printf("\nARP module: Unix domain socket created and listening\n");
    }
    return ;
}


static void sendEthernetframe(EthernetFrame *frame)
{
    struct sockaddr_ll sockAddr;

    bzero(&sockAddr, sizeof(sockAddr));

    sockAddr.sll_family   = PF_PACKET;
    sockAddr.sll_protocol = htons(PROTOCOL_NUMBER);
    sockAddr.sll_halen    = 6;
    sockAddr.sll_ifindex  = 2;
    memcpy(sockAddr.sll_addr, frame->destMAC, 6);

    printf("\nARP module: Sending Ethernet Packet: \n");
    
    memcpy(frame->srcMAC, host_ether, IF_HADDR);
    frame->protocol = htons(PROTOCOL_NUMBER);
    displayEthernetPacket(frame);
    if (sendto(pfSockFd, (void *)frame, sizeof(EthernetFrame), 0,
               (SA *) &sockAddr, sizeof(sockAddr)) == -1)
    {
        err_msg("Error in sending Ethernet packet");
    }
}

void makeARPpacket(msg_type type, arp_packet* packet, struct in_addr sender_ip_addr, struct in_addr dest_ip_addr, char *sender_ethernet_addr, char* dest_ethernet_addr)
{
	printf("\nCreate ARP packet\n");
    packet->type = type;
	packet->protocol = PROTOCOL_NUMBER;
	packet->id = PROTOCOL_NUMBER;
	packet->htype = ARPHRD_ETHER;
	packet->hlen = 6;
	packet->plen = 4;

	packet->sender_ip_addr = sender_ip_addr;
	packet->dest_ip_addr = dest_ip_addr;
	memcpy(packet->sender_ethernet_addr, sender_ethernet_addr, 6);
	memcpy(packet->dest_ethernet_addr, dest_ethernet_addr, 6);

}		


void processARPpacket(arp_packet packet){
	if(packet.type == ARP_REQ){
		//if is dest return reply else update cache
        printf("\nARP: Received ARP_REQ\n");
		if(packet.dest_ip_addr.s_addr == hostip.s_addr){
            printf("\nARP module: Received ARP REQUEST on destination: %s\n", hostname);
			EthernetFrame frame;
			makeARPpacket(ARP_REPLY,&frame.ARP, hostip, packet.sender_ip_addr, host_ether, packet.sender_ethernet_addr);
			//sendEthernetPacket(int sockfd, EthernetFrame *frame)
			memcpy(frame.destMAC, packet.sender_ethernet_addr, IF_HADDR);
			sendEthernetframe(&frame);
			//sendARPreply();
		}
		//update_cache(struct in_addr ipAddr, char *hw_addr, int ifindex, int hatype, int connfd, int forceUpdate){
		update_cache(packet.sender_ip_addr, packet.sender_ethernet_addr, 2, packet.htype, -1, 0);

	}
	else{
		int fd = update_cache(packet.sender_ip_addr, packet.sender_ethernet_addr, 2, packet.htype, -1, 0);
		//send reply on fd
		if(fd != -1){
			char requested_addr[6];
			memcpy(requested_addr,packet.sender_ethernet_addr, 6);
			Writen(fd, requested_addr, 6);
			close(fd);
		}
	}
}

//TODO: closed connectd unix socket
void monitorSockets(){
	fd_set fdSet;
	while(1){
		FD_ZERO(&fdSet);
		FD_SET(pfSockFd, &fdSet);
		FD_SET(unSockFd, &fdSet);
		int maxfd = max(pfSockFd, unSockFd) + 1;
		int s = Select(maxfd, &fdSet, NULL, NULL, NULL);

		if(FD_ISSET(unSockFd, &fdSet)){
            printf("\nARP: Recevied from AREQ\n");
			int fd = Accept(unSockFd, NULL, NULL);
			
			api_packet un_recv_api_packet;
			int r = read(fd, &un_recv_api_packet, sizeof(api_packet));
			//int search_cache(struct in_addr ip, char* hw_addr)
			char hw_addr[6];
			int index = search_cache(un_recv_api_packet.ip, hw_addr);
			if(index == -1){
				//BROADCAST
                printf("\nARP: Does not exist in cache, need to BROADCAST\n");
				update_cache(un_recv_api_packet.ip, NULL, 2, un_recv_api_packet.hatype, fd, 0);
				EthernetFrame frame;
				char broad_ether[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
				makeARPpacket(ARP_REQ, &frame.ARP, hostip, un_recv_api_packet.ip, host_ether, broad_ether);
				//sendEthernetPacket(int sockfd, EthernetFrame *frame)
				memcpy(frame.destMAC, broad_ether, IF_HADDR);
				sendEthernetframe(&frame);
			}
			else{
                printf("\nARP: FOUND value in cache, write on socket: %s\n", ethAddrNtoP(hw_addr));
				Writen(fd, hw_addr, 6);
			}
		}

		if(FD_ISSET(pfSockFd, &fdSet)){

			EthernetFrame frame;
			struct sockaddr_ll sockAddr;
			socklen_t sockLen;
        	sockLen = sizeof(struct sockaddr_ll);
			if (recvfrom(pfSockFd, &frame, sizeof(EthernetFrame), 0, (struct sockaddr *) &sockAddr, &sockLen) < 0){
       			perror("Recv From");
        		exit(0);
    		}

    		if (frame.ARP.protocol != PROTOCOL_NUMBER) {
        		perror("Received invalid identification number.");
        		exit(0);
    		} 

    		processARPpacket(frame.ARP);
		}
	}
}


struct in_addr getInaddr(char *addr){
	char ip[INET_ADDRSTRLEN];
	struct in_addr ipAddr;
	inet_ntop(AF_INET, addr, ip, INET_ADDRSTRLEN);
	inet_pton(AF_INET, ip, &ipAddr);
	return ipAddr;
}

void init(){
    //struct in_addr ip;
	gethostname(hostname, 10);
	hostvm = gethostbyname(hostname);
	hostip = getInaddr(hostvm->h_addr);
	get_hw_addr(host_ether);
	createSockets();
}

int main(){
	init();
	printf("ARP running on %s\n", hostname);
	monitorSockets();
	//unlink(filePath);
    close(pfSockFd);
    close(unSockFd);
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
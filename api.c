#include "arp.h"
#include "api.h"
//{

int areq(struct sockaddr *IPaddr, socklen_t sockaddrlen, hwaddr *HWaddr){

    api_packet packet;
    packet.ifindex = HWaddr->sll_ifindex;
    packet.hatype = HWaddr->sll_hatype;
    packet.ip.s_addr = ((struct sockaddr_in *)IPaddr)->sin_addr.s_addr;

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&(packet.ip),ip,INET_ADDRSTRLEN);
    printf("AREQ: get hwaddr of %s", ip);

    char filePath[1024];

    // Domain to talk to ARP
    struct sockaddr_un sockAddr;
    int sockfd;

    sockfd = socket(AF_LOCAL, SOCK_STREAM, 0);

    bzero(&sockAddr, sizeof(struct sockaddr_un));
    sockAddr.sun_family = AF_LOCAL;
    strcpy(sockAddr.sun_path, ARP_FILE);    
    int c = connect(sockfd, (struct sockaddr *)&sockAddr, sizeof(struct sockaddr_un));
    if(c<0){
        printf("AREQ: connect error\n");
        exit(0);
    }

    int s = write(sockfd, &packet, sizeof(packet));
    if (s<0)
        perror("AREQ: write error");


    // Select to get reply back
    fd_set fdSet;
    struct timeval timeout;

    FD_ZERO(&fdSet);
    FD_SET(sockfd,&fdSet);
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    s =select(sockfd+1,&fdSet,NULL,NULL,&timeout);

    //timeout
    if (s <= 0){
        printf("\n areq timeout");
        close(sockfd);
        return -1;
    }
    else{
        char buf[IF_HADDR]; 

        int r = read(sockfd,buf,IF_HADDR);
        if (r < 0) {
            perror("AREQ:Read error");
            return -1;
        }
        
        memcpy(HWaddr->sll_addr,buf,IF_HADDR);
    }
    close(sockfd);
    return 0;
}


uint16_t in_cksum(uint16_t *addr, int len) {
    int      nleft = len;
    uint32_t sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;
    
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(uint8_t *)(&answer) = *(uint8_t *)w ;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff); 
    sum += (sum >> 16);                 
    answer = ~sum;                      
    return answer;
}

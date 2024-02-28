#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/in_systm.h>
#include <netinet/igmp.h>
#define BUFFER_SIZE 65536
struct dhcphdr {
    u_char		dp_op;		/* packet opcode type */
    u_char		dp_htype;	/* hardware addr type */
    u_char		dp_hlen;	/* hardware addr length */
    u_char		dp_hops;	/* gateway hops */
    u_int32_t		dp_xid;		/* transaction ID */
    u_int16_t		dp_secs;	/* seconds since boot began */	
    u_int16_t		dp_flags;	/* flags */
    struct in_addr	dp_ciaddr;	/* client IP address */
    struct in_addr	dp_yiaddr;	/* 'your' IP address */
    struct in_addr	dp_siaddr;	/* server IP address */
    struct in_addr	dp_giaddr;	/* gateway IP address */
    u_char		dp_chaddr[16];	/* client hardware address */
    u_char		dp_sname[64];	/* server host name */
    u_char		dp_file[128];	/* boot file name */
    u_char		dp_options[0];	/* variable-length options field */
};
void arp_handler(char *buffer, int size) {
	struct arphdr *arp_header = (struct arphdr*)buffer;
	printf("Recived ARP packet:\n");
	printf("Hardware Type: %04X\n", ntohs(arp_header->ar_hrd));
   	printf("Protocol Type: %04X\n", ntohs(arp_header->ar_pro));
    	printf("Hardware Address Length: %u\n", arp_header->ar_hln);
    	printf("Protocol Address Length: %u\n", arp_header->ar_pln);
    	printf("Operation: %04X\n\n", ntohs(arp_header->ar_op));
}
void ip_handler(struct iphdr *ip_header){
	printf("Recived IPV4 packet:\n");
	printf("Version: %u\n", ip_header->version);
	printf("IHL: %u\n", ip_header->ihl);
	printf("Type of Service (TOS): %u\n", ip_header->tos);
	printf("Total Length: %u\n", ntohs(ip_header->tot_len));
	printf("Identification: %u\n", ntohs(ip_header->id));
	printf("Fragment Offset: %u\n", ntohs(ip_header->frag_off));
	printf("Time to Live (TTL): %u\n", ip_header->ttl);
	printf("Protocol: %u\n", ip_header->protocol);
	printf("Header Checksum: %u\n", ntohs(ip_header->check));
	printf("Source IP Address: %u.%u.%u.%u\n",
           (ip_header->saddr >> 24) & 0xFF,
           (ip_header->saddr >> 16) & 0xFF,
           (ip_header->saddr >> 8) & 0xFF,
           ip_header->saddr & 0xFF);
	printf("Destination IP Address: %u.%u.%u.%u\n\n",
           (ip_header->daddr >> 24) & 0xFF,
           (ip_header->daddr >> 16) & 0xFF,
           (ip_header->daddr >> 8) & 0xFF,
           ip_header->daddr & 0xFF);
}
void dhcp_handler(char*buffer, struct iphdr *ip_header){ 
	struct dhcphdr *dhcp_header = (struct dhcphdr*)(buffer +sizeof(struct ethhdr) + ip_header->ihl*4 + sizeof(struct udphdr));
	printf("Recived DHCP packet:\n");
	printf("DHCP Opcode: %d\n", dhcp_header->dp_op);
    	printf("DHCP Hardware Type: %d\n", dhcp_header->dp_htype);
    	printf("DHCP Hardware Address Length: %d\n", dhcp_header->dp_hlen);
   	printf("DHCP Hops: %d\n", dhcp_header->dp_hops);
    	printf("DHCP Transaction ID: %u\n", dhcp_header->dp_xid);
    	printf("DHCP Seconds: %u\n", dhcp_header->dp_secs);
    	printf("DHCP Flags: %u\n", dhcp_header->dp_flags);
    	printf("DHCP Client IP Address: %s\n", inet_ntoa(dhcp_header->dp_ciaddr));
    	printf("DHCP Your IP Address: %s\n", inet_ntoa(dhcp_header->dp_yiaddr));
    	printf("DHCP Server IP Address: %s\n", inet_ntoa(dhcp_header->dp_siaddr));
    	printf("DHCP Gateway IP Address: %s\n", inet_ntoa(dhcp_header->dp_giaddr));

    	printf("DHCP Client Hardware Address (MAC): ");
    	for (int i = 0; i < dhcp_header->dp_hlen; ++i) {
        	printf("%02X ", dhcp_header->dp_chaddr[i]);
    	}
	printf("\n");
	printf("DHCP Server Hostname: %s\n", dhcp_header->dp_sname);
	printf("DHCP Boot file name: %s\n\n",dhcp_header->dp_file);
}
void udp_handler(char *buffer, struct iphdr *ip_header){
	struct udphdr *udp_header = (struct udphdr *)(buffer + sizeof(struct ethhdr) + ip_header->ihl*4);
	printf("Recived UDP packet:\n");
	printf("Source Port: %u\n", ntohs(udp_header->source));
    	printf("Destination Port: %u\n", ntohs(udp_header->dest));
    	printf("Length: %u\n", ntohs(udp_header->len));
    	printf("Checksum: 0x%04X\n\n", ntohs(udp_header->check));
	
	int dest = ntohs(udp_header->dest);
	int source = ntohs(udp_header->source);

	if(((dest == 67) && (source == 68)) || ((dest == 68) && (source == 67)))
		dhcp_handler(buffer,ip_header);
}
void tcp_handler(char *buffer, struct iphdr *ip_header){
	struct tcphdr *tcp_header = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + ip_header->ihl*4);
	printf("Recived TCP packet:\n");
	printf("TCP Source Port: %u\n", ntohs(tcp_header->th_sport));
    	printf("TCP Destination Port: %u\n", ntohs(tcp_header->th_dport));
    	printf("TCP Sequence Number: %u\n", ntohl(tcp_header->th_seq));
    	printf("TCP Acknowledgment Number: %u\n", ntohl(tcp_header->th_ack));
    	printf("TCP Data Offset (Header Length): %u bytes\n", tcp_header->th_off * 4);
    	printf("TCP Flags: ");
    
    	if (tcp_header->th_flags & TH_FIN) printf("FIN ");
    	if (tcp_header->th_flags & TH_SYN) printf("SYN ");
    	if (tcp_header->th_flags & TH_RST) printf("RST ");
    	if (tcp_header->th_flags & TH_PUSH) printf("PSH ");
    	if (tcp_header->th_flags & TH_ACK) printf("ACK ");
    	if (tcp_header->th_flags & TH_URG) printf("URG ");
    	printf("\n");

    	printf("TCP Window Size: %u\n", ntohs(tcp_header->th_win));
    	printf("TCP Checksum: 0x%04X\n", ntohs(tcp_header->th_sum));
    	printf("TCP Urgent Pointer: %u\n\n", ntohs(tcp_header->th_urp));

}
void icmp_handler(char *buffer, struct iphdr *ip_header){
	struct icmphdr * icmp_header = (struct icmphdr*)(buffer + sizeof(struct ethhdr) + ip_header->ihl*4);
	printf("Recived ICMP packet\n");
	printf("ICMP type: %u\n", icmp_header->type);
    	printf("ICMP code: %u\n", icmp_header->code);
    	printf("Checksum: 0x%04X\n\n", ntohs(icmp_header->checksum));
}
void igmp_handler(char *buffer, struct iphdr *ip_header){
	struct igmp *igmp_header = (struct igmp *)(buffer + sizeof(struct ethhdr) + ip_header->ihl*4);
	printf("Recived IPV6 packet\n");
	printf("  Type: %u\n", igmp_header->igmp_type);
    	printf("  Code: %u\n", igmp_header->igmp_code);
    	printf("  Checksum: 0x%04x\n", ntohs(igmp_header->igmp_cksum));
    	printf("  Group Address: %s\n\n", inet_ntoa(igmp_header->igmp_group));
}
void packet_handler(char *buffer, int size) { //main function for packet diff
 	struct ethhdr *eth_header = (struct  ethhdr *)buffer;
 	printf("Destination MAC: ");
	for(int i = 0; i < 5; i++)
		printf("%02X:",eth_header->h_dest[i]);
	printf("%02X\n",eth_header->h_dest[4]);
        
	printf("Source MAC: ");
	for(int i = 0; i < 5; i++)
		printf("%02X:",eth_header->h_source[i]);
	printf("%02X\n\n",eth_header->h_source[5]);

	if(ntohs(eth_header->h_proto) == ETH_P_ARP)
		arp_handler(buffer,size);

	else if(ntohs(eth_header->h_proto) == ETH_P_IP){	
		struct iphdr *ip_header = (struct iphdr*)(buffer + sizeof(struct ethhdr));
		ip_handler(ip_header);

		switch(ip_header->protocol){
			case IPPROTO_UDP:
				udp_handler(buffer,ip_header);
				break;
			case IPPROTO_TCP:
				tcp_handler(buffer,ip_header);
				break;
			case IPPROTO_ICMP:
				icmp_handler(buffer,ip_header);
				break;
			case IPPROTO_IGMP:
				igmp_handler(buffer,ip_header);
				break;	
		}
	}
	else{
		printf("Different protocol\n\n");
	}
	printf("\n\n");
}

int main(int argc, char *argv[]) {
    int sockfd;
    char buffer[BUFFER_SIZE];

    if (argc != 2) {
        printf("Open with interface");
        return 1;
    }

    //create socket 
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1) {
        perror("Błąd podczas tworzenia socketu");
        return 2;
    }

    // promisc
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_nametoindex(argv[1]);

    if (bind(sockfd, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll)) == -1) {
        perror("bind");
        close(sockfd);
        return 3;
    }

    //main loop
    while (1) {
        int size = recv(sockfd, buffer, sizeof(buffer), 0);
	printf("Press enter to check next packet\n");
	getchar();
        if (size < 0) 
		perror("Recvfrom");

    	packet_handler(buffer, size);
    }

    close(sockfd);
    return 0;
}

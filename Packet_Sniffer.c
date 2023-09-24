#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

struct ethheader {
  u_char  ether_dhost[6]; 
  u_char  ether_shost[6];
  u_short ether_type;   
};


struct ipheader {
  unsigned char      iph_ihl:4, 
                     iph_ver:4; 
  unsigned char      iph_tos; 
  unsigned short int iph_len; 
  unsigned short int iph_ident; 
  unsigned short int iph_flag:3, 
                     iph_offset:13;
  unsigned char      iph_ttl;
  unsigned char      iph_protocol; 
  unsigned short int iph_chksum; 
  struct in_addr     iph_sourceip; 
  struct in_addr     iph_destip;  
};


struct tcpheader {
  unsigned short int tcph_srcport; 
  unsigned short int tcph_destport; 
  unsigned int       tcph_seqnum;  
  unsigned int       tcph_acknum;     
  unsigned char      tcph_reserved:4, tcph_offset:4; 
  unsigned char      tcph_flags;
  unsigned short int tcph_win;      
  unsigned short int tcph_chksum;   
  unsigned short int tcph_urgptr;   
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { 
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    printf("Ethernet Header:\n");
    printf("  Source MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("  Destination MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    printf("IP Header:\n");
    printf("  Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("  Destination IP: %s\n", inet_ntoa(ip->iph_destip));


    switch (ip->iph_protocol) {
      case IPPROTO_TCP:
      {
        struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
        printf("TCP Header:\n");
        printf("  Source Port: %u\n", ntohs(tcp->tcph_srcport));
        printf("  Destination Port: %u\n", ntohs(tcp->tcph_destport));

        printf("Message (up to 32 bytes): ");
        int data_length = header->len - (sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcpheader));
        int max_message_length = data_length < 32 ? data_length : 32;
        for (int i = 0; i < max_message_length; i++) {
          printf("%.2X ", packet[sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcpheader) + i]);
        }
        printf("\n");

        return;
      }
      case IPPROTO_ICMP:
        printf("   Protocol: ICMP\n");
        return;
      default:
        printf("   Protocol: others\n");
        return;
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "프로토콜 이름";
  bpf_u_int32 net;
  
  handle = pcap_open_live("enp0s1", BUFSIZ, 1, 1000, errbuf);
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) != 0) {
    pcap_perror(handle, "Error:");
    exit(EXIT_FAILURE);
  }

  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle); 
  return 0;
}

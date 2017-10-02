/* capture packet and display TCP/IPv4 header */

#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>    /* inet_ntop */
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define COUNT 20    /* number to capture packets */
#define TIMEOUT -1    /* for pcap_open_live */
#define MODE 0    /* promiscuous mode */

void callback(u_char *user, const struct pcap_pkthdr *p_hdr, const u_char *packet);

int main(int argc, char *argv[])
{
  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  if ((dev = pcap_lookupdev(errbuf)) == NULL)
  {
    printf("%s\n", errbuf);
    return 1;
  }

  printf("Device\t\t: %s\n", dev);

  if ((handle = pcap_open_live(dev, BUFSIZ, MODE, TIMEOUT, errbuf)) == NULL) {
    printf("%s\n", errbuf);
    return 1;
  }

  if (pcap_loop(handle, COUNT, callback, NULL) < 0) {
    puts("Can not capture packet");
    return 1;
  }

  pcap_close(handle);

  return 0;
}

void callback(u_char *user, const struct pcap_pkthdr *p_hdr, const u_char *packet) {
  struct ether_header *e_hdr;
  struct ip *ip_hdr;
  struct tcphdr *t_hdr;

  if (p_hdr->len < sizeof(struct ether_header)) {
    puts("Defective packet\n");
    return;
  }

  e_hdr = (struct ether_header *)packet;

  if (ntohs(e_hdr->ether_type) != ETHERTYPE_IP) {
    printf("This packet is 0x%04x\n\n", ntohs(e_hdr->ether_type));
    return;
  }

  ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));

  if (ip_hdr->ip_v != 4){
    puts("Unknown packet\n");
    return;
  }

  if (ip_hdr->ip_p != 6) {
    printf("Protocol number of this packet is %02d\n", ip_hdr->ip_p);
    return;
  }

  t_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

  printf("Source port\t: %u\n", ntohs(t_hdr->source));
  printf("Destination port: %u\n", ntohs(t_hdr->dest));
  printf("Sequence number : %u\n", ntohl(t_hdr->seq));
  printf("Ack number\t: %u\n", ntohl(t_hdr->ack_seq));
  printf("Data Offset\t: %d\n", t_hdr->doff);
  printf("Reserved 1\t: %d\n", t_hdr->res1);
  printf("Reserved 2\t: %d\n", t_hdr->res2);
  printf("Urg Flag\t: %d\n", t_hdr->urg);
  printf("Ack Flag\t: %d\n", t_hdr->ack);
  printf("Push Flag\t: %d\n", t_hdr->psh);
  printf("Reset Flag\t: %d\n", t_hdr->rst);
  printf("Syn Flag\t: %d\n", t_hdr->syn);
  printf("Fin Flag\t: %d\n", t_hdr->fin);
  printf("Window size\t: %u\n", ntohs(t_hdr->window));
  printf("Checksum\t: %u\n", ntohs(t_hdr->check));
  printf("Urgent pointer\t: %u\n", ntohs(t_hdr->urg_ptr));
  putchar('\n');
}

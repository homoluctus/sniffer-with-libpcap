/* packet capture and display UDP/IPv4 header */

#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define COUNT 20    /* number to capture packets */
#define TIMEOUT -1    /* for pcap_open_live() */
#define MODE 0    /* promiscuous mode */

void callback(u_char *user, const struct pcap_pkthdr *p_hdr, const u_char *packet);

int main(int argc, char *argv[])
{
  char *dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  if ((dev = pcap_lookupdev(errbuf)) == NULL) {
    printf("%s\n", errbuf);
    return 1;
  }

  if ((handle = pcap_open_live(dev, BUFSIZ, MODE, TIMEOUT, errbuf)) == NULL) {
    printf("%s\n", errbuf);
    return 1;
  }

  if (pcap_loop(handle, COUNT, callback, NULL) < 0) {
    puts("Can not capture packets");
    return 1;
  }

  pcap_close(handle);

  return 0;
}

void callback(u_char *user, const struct pcap_pkthdr *p_hdr, const u_char *packet)
{
  struct ether_header *e_hdr;
  struct ip *ip_hdr;
  struct udphdr *u_hdr;

  if (p_hdr->len < sizeof(struct ether_header)) {
    puts("Defevtive packet\n");
    return;
  }

  e_hdr = (struct ether_header *)packet;

  if (ntohs(e_hdr->ether_type) != ETHERTYPE_IP) {
    printf("This packet is 0x%04x\n", ntohs(e_hdr->ether_type));
    return;
  }

  ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));

  if (ip_hdr->ip_v != 4){
    printf("Unkown packet");
    return;
  }

  if (ip_hdr->ip_p != 17) {
    puts("This packet is not UDP");
    return;
  }

  u_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

  printf("Source port\t: %u\n", ntohs(u_hdr->source));
  printf("Destination port: %u\n", ntohs(u_hdr->dest));
  printf("Length\t\t: %u\n", ntohs(u_hdr->len));
  //printf("Checksum\t: %u\n", ntohs(u_hdr->check));
  putchar('\n');
}

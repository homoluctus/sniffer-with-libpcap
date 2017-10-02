/* capture packets and display IPv4 header */

#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>    /* for ntohs() */
#include <net/ethernet.h>
#include <netinet/ip.h>

#define COUNT 20    /* number to capture packets */
#define TIMEOUT -1    /* for pcap_open_live */
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

  printf("Device: %s\n", dev);

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

void callback(u_char *user, const struct pcap_pkthdr *p_hdr, const u_char *packet) {
  struct ether_header *e_hdr;
  struct ip *ip_hdr;

  if (p_hdr->len < sizeof(struct ether_header)) {
    puts("Defective packet");
    return;
  }

  e_hdr = (struct ether_header *)packet;

  if (ntohs(e_hdr->ether_type) != ETHERTYPE_IP) {
    puts("This packet is not IPv4");
    return;
  }

  /* point the beginning of struct ip */
  ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));

  if (ip_hdr->ip_v != 4) {
    puts("Unknown version");
    return;
  }

  printf("Version\t\t\t: %x\n", ip_hdr->ip_v);
  printf("IPv4 header length\t: %x\n", ip_hdr->ip_hl);
  printf("TOS\t\t\t: 0x%02x\n", ip_hdr->ip_tos);
  printf("Total length\t\t: %u\n", ntohs(ip_hdr->ip_len));
  printf("Identification\t\t: %u\n", ntohs(ip_hdr->ip_id));
  printf("Flagment offset\t\t: 0x%04x\n", ntohs(ip_hdr->ip_off));
  printf("TTL\t\t\t: %u\n", ip_hdr->ip_ttl);
  printf("Protocol\t\t: 0x%02x\n", ip_hdr->ip_p);
  //printf("Checksum\t\t: %u\n", ntohs(ip_hdr->ip_sum));
  printf("SRC address\t\t: %s\n", inet_ntoa(ip_hdr->ip_src));
  printf("DST address\t\t: %s\n\n", inet_ntoa(ip_hdr->ip_dst));
}

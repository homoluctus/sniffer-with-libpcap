/* capture packets and display ethernet frame */

#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#define COUNT 20    /* number to capture packets */
#define TIMEOUT -1    /* for pcap_open_live() */
#define MODE 0    /* promiscuous mode*/

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
    puts("Can not capture packet");
    return 1;
  }

  pcap_close(handle);

  return 0;
}

void callback(u_char *user, const struct pcap_pkthdr *p_hdr, const u_char *packet)
{
  int i;    /* use to display mac address */
  u_int type;    /* ethernet type */
  struct ether_header *e_hdr;    /* the explanation is written in <net/ethernet.h> */

  printf("Packet length: %d\n", p_hdr->len);

  e_hdr = (struct ether_header *)packet;

  printf("Ethernet type: ");
  type = ntohs(e_hdr->ether_type);
  switch (type) {
    case ETHERTYPE_IP:
      printf("0x%04x (IPv4)\n", type);
      break;
    case ETHERTYPE_ARP:
      printf("0x%04x (ARP)\n", type);
      break;
    case ETHERTYPE_IPV6:
      printf("0x%04x (IPv6)\n", type);
      break;
    case ETHERTYPE_LOOPBACK:
      printf("0x%04x (LOOPBACK)\n", type);
      break;
    default:
      printf("0x%04x\n", type);
      break;
  }

  for (i = 0; i < ETH_ALEN; i++) {
    /* source mac address */
    printf("%02x%s", e_hdr->ether_shost[i], (i == (ETH_ALEN - 1)) ? " > " : ":");
  }

  for (i = 0; i < ETH_ALEN; i++) {
    /* destination mac address */
    printf("%02x%s", e_hdr->ether_dhost[i], (i == (ETH_ALEN - 1)) ? "\n\n" : ":");
  }
}

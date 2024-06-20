#ifndef LF_ARP_H
#define LF_ARP_H

#define LF_ARP_TIMEOUT_TIME 3 /* seconds */

/*
 * Sends an ARP request on
 * interface <ifname> to IPv4 address <ip>.
 * Returns 0 on success.
 */
int
arp_request(const char *ifname, uint32_t ip, uint8_t *ether);

#endif /* LF_ARP_H */
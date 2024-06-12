#ifndef LF_ARP_H
#define LF_ARP_H

#define PROTO_ARP       0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE         1
#define MAC_LENGTH      6
#define IPV4_LENGTH     4
#define ARP_REQUEST     0x01
#define ARP_REPLY       0x02
#define ARP_BUF_SIZE    60

struct arp_header {
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hardware_len;
	uint8_t protocol_len;
	uint16_t opcode;
	uint8_t sender_mac[MAC_LENGTH];
	uint8_t sender_ip[IPV4_LENGTH];
	uint8_t target_mac[MAC_LENGTH];
	uint8_t target_ip[IPV4_LENGTH];
};

/*
 * Sends an ARP request on
 * interface <ifname> to IPv4 address <ip>.
 * Returns 0 on success.
 */
int
arp_request(const char *ifname, uint32_t ip, uint8_t *ether);

#endif /* LF_ARP_H */
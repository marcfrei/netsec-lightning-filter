#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../log/log.h"
#include "arp.h"

#define LF_ARP_LOG(level, ...) LF_LOG(level, "ARP: " __VA_ARGS__)

// The code below is taken and adapted from
// https://stackoverflow.com/questions/16710040/arp-request-and-reply-using-c-socket-programming

/*
 * Converts struct sockaddr with an IPv4 address to network byte order uin32_t.
 * Returns 0 on success.
 */
int
int_ip4(struct sockaddr *addr, uint32_t *ip)
{
	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *i = (struct sockaddr_in *)addr;
		*ip = i->sin_addr.s_addr;
		return 0;
	} else {
		LF_ARP_LOG(ERR, "Not AF_INET\n");
		return 1;
	}
}

/*
 * Writes interface IPv4 address as network byte order to ip.
 * Returns 0 on success.
 */
int
get_if_ip4(int fd, const char *ifname, uint32_t *ip)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	if (strlen(ifname) > (IFNAMSIZ - 1)) {
		LF_ARP_LOG(ERR, "Too long interface name \n");
		return -1;
	}

	strcpy(ifr.ifr_name, ifname);
	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
		LF_ARP_LOG(ERR, "SIOCGIFADDR");
		return -1;
	}

	if (int_ip4(&ifr.ifr_addr, ip)) {
		return -1;
	}

	return 0;
}

/*
 * Sends an ARP who-has request to dst_ip
 * on interface ifindex, using source mac src_mac and source ip src_ip.
 */
int
send_arp(int fd, int ifindex, uint16_t *src_mac, uint32_t src_ip,
		uint32_t dst_ip)
{
	uint8_t buffer[ARP_BUF_SIZE];
	memset(buffer, 0, sizeof(buffer));

	struct sockaddr_ll socket_address;
	socket_address.sll_family = AF_PACKET;
	socket_address.sll_protocol = htons(ETH_P_ARP);
	socket_address.sll_ifindex = ifindex;
	socket_address.sll_hatype = htons(ARPHRD_ETHER);
	socket_address.sll_pkttype = (PACKET_BROADCAST);
	socket_address.sll_halen = MAC_LENGTH;
	socket_address.sll_addr[6] = 0x00;
	socket_address.sll_addr[7] = 0x00;

	struct ethhdr *send_req = (struct ethhdr *)buffer;
	struct arp_header *arp_req =
			(struct arp_header *)(buffer + ETH2_HEADER_LEN);
	ssize_t ret = 0;

	// Broadcast
	memset(send_req->h_dest, 0xff, MAC_LENGTH);

	// Target MAC zero
	memset(arp_req->target_mac, 0x00, MAC_LENGTH);

	// Set source mac to our MAC address
	memcpy(send_req->h_source, src_mac, MAC_LENGTH);
	memcpy(arp_req->sender_mac, src_mac, MAC_LENGTH);
	memcpy(socket_address.sll_addr, src_mac, MAC_LENGTH);

	/* Setting protocol of the packet */
	send_req->h_proto = htons(ETH_P_ARP);

	/* Creating ARP request */
	arp_req->hardware_type = htons(HW_TYPE);
	arp_req->protocol_type = htons(ETH_P_IP);
	arp_req->hardware_len = MAC_LENGTH;
	arp_req->protocol_len = IPV4_LENGTH;
	arp_req->opcode = htons(ARP_REQUEST);

	memcpy(arp_req->sender_ip, &src_ip, sizeof(uint32_t));
	memcpy(arp_req->target_ip, &dst_ip, sizeof(uint32_t));

	ret = sendto(fd, buffer, 42, 0, (struct sockaddr *)&socket_address,
			sizeof(socket_address));
	if (ret == -1) {
		return -1;
	}
	return 0;
}

/*
 * Gets interface information by name:
 * IPv4
 * MAC
 * ifindex
 */
int
get_if_info(const char *ifname, uint32_t *ip, uint16_t *mac, int *ifindex)
{
	int err = -1;
	struct ifreq ifr;
	int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sd <= 0) {
		LF_ARP_LOG(ERR, "socket");
		goto out;
	}
	if (strlen(ifname) > (IFNAMSIZ - 1)) {
		LF_ARP_LOG(ERR, "Too long interface name, MAX=%i\n", IFNAMSIZ - 1);
		goto out;
	}

	strcpy(ifr.ifr_name, ifname);

	// Get interface index using name
	if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
		LF_ARP_LOG(ERR, "SIOCGIFINDEX");
		goto out;
	}
	*ifindex = ifr.ifr_ifindex;

	// Get MAC address of the interface
	if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
		LF_ARP_LOG(ERR, "SIOCGIFINDEX");
		goto out;
	}

	// Copy mac address to output
	memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

	if (get_if_ip4(sd, ifname, ip)) {
		goto out;
	}

	err = 0;
out:
	if (sd > 0) {
		close(sd);
	}
	return err;
}

/*
 * Creates a raw socket that listens for ARP traffic on specific ifindex.
 * Writes out the socket's FD.
 * Return 0 on success.
 */
int
bind_arp(int ifindex, int *fd)
{
	int ret = -1;

	// Submit request for a raw socket descriptor.
	*fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (*fd < 1) {
		LF_ARP_LOG(ERR, "socket");
		goto out;
	}

	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(struct sockaddr_ll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex;
	if (bind(*fd, (struct sockaddr *)&sll, sizeof(struct sockaddr_ll)) < 0) {
		LF_ARP_LOG(ERR, "bind");
		goto out;
	}

	ret = 0;
out:
	if (ret && *fd > 0) {
		close(*fd);
	}
	return ret;
}

/*
 * Reads a single ARP reply from fd.
 * Return 0 on success.
 */
int
read_arp(int fd, uint32_t ip, uint8_t *ether)
{
	uint8_t buffer[ARP_BUF_SIZE];
	struct ethhdr *rcv_resp = (struct ethhdr *)buffer;
	struct arp_header *arp_resp =
			(struct arp_header *)(buffer + ETH2_HEADER_LEN);

	ssize_t length = recvfrom(fd, buffer, ARP_BUF_SIZE, 0, NULL, NULL);
	if (length == -1) {
		return -1;
	}
	if (ntohs(rcv_resp->h_proto) != PROTO_ARP) {
		return -1;
	}
	if (ntohs(arp_resp->opcode) != ARP_REPLY) {
		return -1;
	}
	if (*(uint32_t *)arp_resp->sender_ip != ip) {
		return -1;
	}

	memcpy(ether, arp_resp->sender_mac, 6);
	return 0;
}

int
arp_request(const char *ifname, uint32_t ip, uint8_t *ether)
{
	int ret = -1;
	int arp_fd = 0;

	uint32_t src;
	int ifindex;
	uint16_t mac[MAC_LENGTH];
	if (get_if_info(ifname, &src, mac, &ifindex)) {
		LF_ARP_LOG(ERR,
				"get_if_info failed, interface %s not found or no IP set? \n",
				ifname);
		goto out;
	}
	if (bind_arp(ifindex, &arp_fd)) {
		LF_ARP_LOG(ERR, "Failed to bind \n");
		goto out;
	}

	if (send_arp(arp_fd, ifindex, mac, src, ip)) {
		LF_ARP_LOG(ERR, "Failed to send_arp \n");
		goto out;
	}

	int msec = 0, trigger = 3000; /* 3s */
	clock_t before = clock();
	while (msec < trigger) {
		int r = read_arp(arp_fd, ip, ether);
		if (r == 0) {
			ret = 0;
			break;
		}
		clock_t difference = clock() - before;
		msec = difference * 1000 / CLOCKS_PER_SEC;
	}

out:
	if (arp_fd) {
		close(arp_fd);
		arp_fd = 0;
	}
	return ret;
}

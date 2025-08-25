#pragma once

#include <arpa/inet.h>    // inet_aton, htons
#include <net/ethernet.h> // ETH_P_ARP, ETH_ALEN
#include <net/if.h>
#include <netinet/if_ether.h> // struct ethhdr, struct ether_arp
#include <netpacket/packet.h>
#include <stdexcept>
#include <string.h> // memcpy, memset
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace dsarp {

inline std::vector<uint8_t> buildRequest(const char *src_mac_str, const char *src_ip_str,
                                         const char *target_ip_str) {
    // Parse source MAC
    unsigned int mac_bytes[6];
    if (sscanf(src_mac_str, "%x:%x:%x:%x:%x:%x", &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
               &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]) != 6) {
        throw std::runtime_error("invalid source MAC string");
    }
    uint8_t src_mac[6];
    for (int i = 0; i < 6; i++)
        src_mac[i] = static_cast<uint8_t>(mac_bytes[i]);

    // Parse source/target IP
    in_addr src_ip{}, target_ip{};
    if (inet_aton(src_ip_str, &src_ip) == 0)
        throw std::runtime_error("invalid source IP");
    if (inet_aton(target_ip_str, &target_ip) == 0)
        throw std::runtime_error("invalid target IP");

    // Ethernet + ARP header
    struct {
        struct ethhdr eth;
        struct ether_arp arp;
    } __attribute__((packed)) pkt{};

    // Ethernet header
    memset(pkt.eth.h_dest, 0xff, ETH_ALEN); // broadcast
    memcpy(pkt.eth.h_source, src_mac, ETH_ALEN);
    pkt.eth.h_proto = htons(ETH_P_ARP);

    // ARP header
    pkt.arp.arp_hrd = htons(ARPHRD_ETHER);
    pkt.arp.arp_pro = htons(ETH_P_IP);
    pkt.arp.arp_hln = ETH_ALEN;
    pkt.arp.arp_pln = 4;
    pkt.arp.arp_op = htons(ARPOP_REQUEST);

    memcpy(pkt.arp.arp_sha, src_mac, ETH_ALEN);
    memcpy(pkt.arp.arp_spa, &src_ip, 4);
    memset(pkt.arp.arp_tha, 0x00, ETH_ALEN);
    memcpy(pkt.arp.arp_tpa, &target_ip, 4);

    std::vector<uint8_t> buf(sizeof(pkt));
    memcpy(buf.data(), &pkt, sizeof(pkt));
    return buf;
}

inline void broadcast(const std::vector<uint8_t> &pkt, const char *ifname) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0)
        throw std::runtime_error("socket failed");

    sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_ifindex = if_nametoindex(ifname);
    addr.sll_halen = ETH_ALEN;
    memset(addr.sll_addr, 0xff, ETH_ALEN); // broadcast

    if (sendto(sock, pkt.data(), pkt.size(), 0, (sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        throw std::runtime_error("sendto failed");
    }

    close(sock);
}

inline void listenReplies(const char *ifname, int timeout_sec) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0)
        throw std::runtime_error("socket failed");

    sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_ifindex = if_nametoindex(ifname);

    if (bind(sock, (sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        throw std::runtime_error("bind failed");
    }

    timeval tv{};
    tv.tv_sec = timeout_sec;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t buf[1500];
    while (true) {
        ssize_t len = recv(sock, buf, sizeof(buf), 0);
        if (len < 0)
            break; // timeout or error

        if (len >= (int)(sizeof(ethhdr) + sizeof(ether_arp))) {
            auto *eth = (ethhdr *)buf;
            if (ntohs(eth->h_proto) != ETH_P_ARP)
                continue;

            auto *arp = (ether_arp *)(buf + sizeof(ethhdr));
            if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REPLY) {
                char sender_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, arp->arp_spa, sender_ip, sizeof(sender_ip));

                printf("Got ARP reply: %s is at %02x:%02x:%02x:%02x:%02x:%02x\n", sender_ip,
                       arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2], arp->arp_sha[3],
                       arp->arp_sha[4], arp->arp_sha[5]);
            }
        }
    }

    close(sock);
}

} // namespace dsarp
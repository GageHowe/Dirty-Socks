#pragma once

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "ip.hpp"

namespace dsudp {

namespace internal {
inline uint16_t udp_checksum(const iphdr *iph, const udphdr *udph, const uint8_t *payload,
                             size_t payload_len) {
    struct pseudo_header {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t udp_length;
    } psh;

    psh.src_addr = iph->saddr;
    psh.dst_addr = iph->daddr;
    psh.zero = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = udph->len;

    // Build buffer for checksum: pseudo-header + UDP header + payload
    std::vector<uint8_t> buf(sizeof(psh) + sizeof(udphdr) + payload_len);
    memcpy(buf.data(), &psh, sizeof(psh));
    memcpy(buf.data() + sizeof(psh), udph, sizeof(udphdr));
    memcpy(buf.data() + sizeof(psh) + sizeof(udphdr), payload, payload_len);

    return dsip::internal::checksum((unsigned short *)buf.data(), buf.size());
}
} // namespace internal

inline int socket() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        throw std::runtime_error("socket error");
    }
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        throw std::runtime_error("socket error");
    }
    return sock;
}

// Build a RFC 768 - compliant UDP packet with variable length
inline std::vector<uint8_t> buildPacket() {
    const char payload[] = "hello there";
    constexpr size_t payload_len = sizeof(payload) - 1;

    size_t packet_len = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;
    std::vector<uint8_t> packet(packet_len);

    auto *iph = (struct iphdr *)packet.data();
    auto *udph = (struct udphdr *)(packet.data() + sizeof(struct iphdr));
    auto *data = packet.data() + sizeof(struct iphdr) + sizeof(struct udphdr);

    memcpy(data, payload, payload_len);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(packet_len);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 83; // pseudorandom default to throw off TTL-based geolocation
    iph->protocol = IPPROTO_UDP;
    iph->saddr = inet_addr("127.0.0.1");
    iph->daddr = inet_addr("127.0.0.1");
    iph->check = 0;

    udph->source = htons(53);
    udph->dest = htons(53);
    udph->len = htons(sizeof(struct udphdr) + payload_len);
    udph->check = 0;

    return packet;
}

inline void setSrcIP(std::vector<uint8_t> &packet, const char *src_ip) {
    iphdr *iph = (struct iphdr *)packet.data();
    iph->saddr = inet_addr(src_ip);
}

// Sets the source address in the IP header.
inline std::string getSrcIP(const std::vector<uint8_t> &packet) {
    const iphdr *iph = reinterpret_cast<const iphdr *>(packet.data());
    in_addr addr{};
    addr.s_addr = iph->saddr;
    return std::string(inet_ntoa(addr));
}

// Sets the destination port in the IP header.
inline void setDstIP(std::vector<uint8_t> &packet, const char *dst_ip) {
    iphdr *iph = (struct iphdr *)packet.data();
    iph->daddr = inet_addr(dst_ip);
}

// Sets the source port in the IP header.
inline void setSrcPort(std::vector<uint8_t> &packet, uint16_t port) {
    udphdr *udph = (struct udphdr *)(packet.data() + sizeof(struct iphdr));
    udph->source = htons(port);
}

// Sets the destination port in the IP header.
inline void setDstPort(std::vector<uint8_t> &packet, uint16_t port) {
    udphdr *udph = (struct udphdr *)(packet.data() + sizeof(struct iphdr));
    udph->dest = htons(port);
}

// Sets new UDP payload, adjusts header fields and packet size.
inline void setContent(std::vector<uint8_t> &packet, const char *data, int data_len) {
    size_t new_len = sizeof(struct iphdr) + sizeof(struct udphdr) + data_len;
    packet.resize(new_len);

    iphdr *iph = (struct iphdr *)packet.data();
    udphdr *udph = (struct udphdr *)(packet.data() + sizeof(struct iphdr));
    char *payload = (char *)(packet.data() + sizeof(struct iphdr) + sizeof(struct udphdr));

    memcpy(payload, data, data_len);

    iph->tot_len = htons(new_len);
    iph->check = 0;

    udph->len = htons(sizeof(struct udphdr) + data_len);
    // udph->check = 0;
}

// Apply udp and ip checksums. Use this before sending a packet
inline void finalizeChecksum(std::vector<uint8_t> &packet) {
    iphdr *iph = reinterpret_cast<iphdr *>(packet.data());
    udphdr *udph = reinterpret_cast<udphdr *>(packet.data() + sizeof(iphdr));

    const uint8_t *payload = packet.data() + sizeof(iphdr) + sizeof(udphdr);
    size_t payload_len = packet.size() - sizeof(iphdr) - sizeof(udphdr);

    iph->check = 0;
    iph->check = dsip::internal::checksum(reinterpret_cast<unsigned short *>(iph), sizeof(iphdr));

    udph->check = 0;
    udph->check = internal::udp_checksum(iph, udph, payload, payload_len);
}

// Sends the packet. Make sure to call finalizeChecksum first to ensure packet is valid
inline int send(int sock, const std::vector<uint8_t> &packet) {
    const struct iphdr *iph = (const struct iphdr *)packet.data();

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = iph->daddr;

    ssize_t result =
        sendto(sock, packet.data(), packet.size(), 0, (struct sockaddr *)&dest, sizeof(dest));

    if (result < 0) {
        perror("sendto failed");
    } else {
        printf("Sent packet to %s\n", inet_ntoa(dest.sin_addr));
    }

    return result;
}

} // namespace dsudp
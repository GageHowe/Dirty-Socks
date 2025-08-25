#pragma once

#include "ip.hpp"
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

// for tcp
struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_length;
};

inline void finalizeChecksum(std::vector<uint8_t> &packet, int data_len) {
    auto *iph = (struct iphdr *)packet.data();
    auto *tcph = (struct tcphdr *)(packet.data() + sizeof(struct iphdr));
    const char *data = (char *)(packet.data() + sizeof(struct iphdr) + sizeof(struct tcphdr));

    int tcp_len = sizeof(struct tcphdr) + data_len;

    struct pseudo_header {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t reserved;
        uint8_t protocol;
        uint16_t tcp_len;
    } psh;

    psh.src_addr = iph->saddr;
    psh.dst_addr = iph->daddr;
    psh.reserved = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_len = htons(tcp_len);

    int psize = sizeof(psh) + tcp_len;
    std::vector<uint8_t> pseudogram(psize);

    memcpy(pseudogram.data(), &psh, sizeof(psh));
    memcpy(pseudogram.data() + sizeof(psh), tcph, tcp_len);

    tcph->check = 0;
    tcph->check = dsip::checksum((unsigned short *)pseudogram.data(), psize);
}

inline std::vector<uint8_t> buildPacket(const std::string &payload) {
    int payload_len = payload.size();
    int packet_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len;

    std::vector<uint8_t> packet(packet_len);

    auto *iph = (struct iphdr *)packet.data();
    auto *tcph = (struct tcphdr *)(packet.data() + sizeof(struct iphdr));
    char *data = (char *)(packet.data() + sizeof(struct iphdr) + sizeof(struct tcphdr));

    memcpy(data, payload.data(), payload_len);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(packet_len);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 83; // pseudorandom default to throw off TTL-based geolocation
    iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr("127.0.0.1");
    iph->daddr = inet_addr("127.0.0.1");
    iph->check = 0;
    iph->check = dsip::checksum((unsigned short *)iph, sizeof(struct iphdr));

    tcph->source = htons(80);
    tcph->dest = htons(80);
    tcph->seq = htonl(0);     // sequence number, auto increment when maintaining a connection
    tcph->ack_seq = htonl(0); // acknowledgement: "I’ve received up to byte N - 1"
    tcph->doff = 5;           // Data Offset / Header Length; no options used here

    tcph->syn = 1; // synchronization flag; requests connection
    tcph->ack = 0;
    tcph->psh = 0;
    tcph->fin = 0;               // request graceful close
    tcph->rst = 0;               // immediately terminates the connection
    tcph->urg = 0;               // if urgent pointer is valid; urg_ptr is rarely used in practice
    tcph->window = htons(65535); // window size (how many bytes sender is willing to recieve)
    tcph->check = 0;
    tcph->urg_ptr = 0;

    finalizeChecksum(packet, payload_len);
    return packet;
}
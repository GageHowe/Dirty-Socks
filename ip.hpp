#pragma once

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>

namespace dsip {

namespace internal {

// standard 16-bit internet checksum (RFC 1071)
inline uint16_t checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (short)~sum;
}

} // namespace internal

// Set this packet's time to live
// UDP: must call verifyChecksum after touching IP header
inline void IP_SetTTL(char *buffer, uint8_t ttl) {
    struct iphdr *iph = (struct iphdr *)buffer;
    iph->ttl = ttl;
}

// UDP: must call verifyChecksum after touching IP header

} // namespace dsip

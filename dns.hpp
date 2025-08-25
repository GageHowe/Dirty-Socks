#pragma once

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

// TODO: verify this works
inline std::vector<uint8_t> build_dns_query(const std::string &domain) {
    std::vector<uint8_t> query;

    // Header
    query.push_back(0x12);
    query.push_back(0x34); // Transaction ID
    query.push_back(0x01);
    query.push_back(0x00); // Standard query
    query.push_back(0x00);
    query.push_back(0x01); // QDCOUNT = 1
    query.push_back(0x00);
    query.push_back(0x00); // ANCOUNT
    query.push_back(0x00);
    query.push_back(0x00); // NSCOUNT
    query.push_back(0x00);
    query.push_back(0x00); // ARCOUNT

    // Question section
    size_t start = 0;
    while (true) {
        size_t dot = domain.find('.', start);
        size_t len = (dot == std::string::npos) ? domain.size() - start : dot - start;
        query.push_back(static_cast<uint8_t>(len));
        query.insert(query.end(), domain.begin() + start, domain.begin() + start + len);
        if (dot == std::string::npos)
            break;
        start = dot + 1;
    }
    query.push_back(0x00); // Null terminator
    query.push_back(0x00);
    query.push_back(0x01); // QTYPE = A
    query.push_back(0x00);
    query.push_back(0x01); // QCLASS = IN

    return query;
}
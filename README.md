# DirtySocks

A simple header-only raw sockets library. DirtySocks follows an opinionated set of developer guidelines for enforcing best practices, modularity, and safety

## design

This library is designed with the following guidelines:

* Value backward compatibility (down to c++11)
* banned keywords: class (use struct instead), new, delete/delete[] (prefer smart pointers unless very carefully for optimization), malloc/calloc, free, enum, #define (prefer enum class, constexpr, inline), auto, null, using namespace, cout/endl/etc
* No inheritance
* High performance and flexibility

## examples

Network stress test

```cpp
// ddos-like send loop with large packets and random source ip and random dest ports
#include <cstdlib>
#include <ctime>
#include "ip.hpp"
#include "udp.hpp" // this file

int main() {
    srand(time(nullptr));
    int sock = dsudp::Socket();

    for (int i = 0; i < 1000; i++) {
        auto packet = dsudp::buildPacket();

        // Randomize source IP
        char src_ip[16];
        sprintf(src_ip, "192.168.%d.%d", rand() % 256, rand() % 256);
        dsudp::setSrcIP(packet, src_ip);

        // Randomize destination port
        dsudp::setDstPort(packet, 1024 + rand() % 64511);

        // Create large payload
        std::string payload(1400, 'A');
        dsudp::setContent(packet, payload.c_str(), payload.size());

        dsudp::finalizeChecksum(packet);
        dsudp::send(sock, packet);
    }

    close(sock);
}
```

Send messages

```cpp
// convert a string and send it to some destination
#include "ip.hpp"
#include "udp.hpp"

int main() {
    int sock = dsudp::Socket();
    auto packet = dsudp::buildPacket();

    // Configure IP/Port
    dsudp::setSrcIP(packet, "192.168.1.100");
    dsudp::setDstIP(packet, "192.168.1.200");
    dsudp::setSrcPort(packet, 12345);
    dsudp::setDstPort(packet, 5000);

    // Set custom payload
    const char* msg = "Hello from raw UDP!";
    dsudp::setContent(packet, msg, strlen(msg));

    // Finalize and send
    dsudp::finalizeChecksum(packet);
    dsudp::send(sock, packet);

    close(sock);
}

```

Receive and echo packets

```cpp
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>

#include "ip.hpp"
#include "udp.hpp"  // Your library

int main() {
	// Open raw UDP socket
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if (sock < 0) {
		perror("socket");
		return 1;
	}

	uint8_t buffer[65535];

	while (true) {
		ssize_t len = recv(sock, buffer, sizeof(buffer), 0);
		if (len < 0) {
			perror("recv");
			break;
		}

		iphdr* iph = reinterpret_cast<iphdr*>(buffer);
		udphdr* udph = reinterpret_cast<udphdr*>(buffer + iph->ihl * 4);
		uint8_t* payload = buffer + iph->ihl * 4 + sizeof(udphdr);
		size_t payload_len = len - iph->ihl * 4 - sizeof(udphdr);

		char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &iph->saddr, src_ip, sizeof(src_ip));
		inet_ntop(AF_INET, &iph->daddr, dst_ip, sizeof(dst_ip));

		printf("Received UDP packet from %s:%d -> %s:%d | %zu bytes payload\n",
			src_ip, ntohs(udph->source),
			dst_ip, ntohs(udph->dest),
			payload_len);

		// Echo back: swap src/dst IP + ports
		std::vector<uint8_t> packet(buffer, buffer + len);

		dsudp::setSrcIP(packet, dst_ip);
		dsudp::setDstIP(packet, src_ip);

		dsudp::setSrcPort(packet, ntohs(udph->dest));
		dsudp::setDstPort(packet, ntohs(udph->source));

		// (Optional) modify payload here
		// std::string reply = "Echo: " + std::string((char*)payload, payload_len);
		// dsudp::setContent(packet, reply.c_str(), reply.size());

		dsudp::finalizeChecksum(packet);
		dsudp::send(sock, packet);
	}

	close(sock);
}
```
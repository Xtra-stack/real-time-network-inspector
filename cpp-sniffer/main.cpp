#include <iostream>
#include <string>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <arpa/inet.h>
#endif

#include <pcap.h>

#ifdef _WIN32
#pragma pack(push, 1)
#endif
struct EthernetHeader {
    unsigned char destination[6];
    unsigned char source[6];
    unsigned short type;
};
#ifdef _WIN32
#pragma pack(pop)
#endif

struct IpHeader {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    unsigned char ihl : 4;
    unsigned char version : 4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    unsigned char version : 4;
    unsigned char ihl : 4;
#else
#error "Byte order not supported"
#endif
    unsigned char tos;
    unsigned short totalLength;
    unsigned short identification;
    unsigned short fragmentOffset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short headerChecksum;
    struct in_addr sourceAddress;
    struct in_addr destinationAddress;
};

std::string getProtocolName(unsigned char protocol) {
    switch (protocol) {
        case 6:
            return "TCP";
        case 17:
            return "UDP";
        case 1:
            return "ICMP";
        default:
            return "OTHER";
    }
}

std::string formatTimestamp(const struct timeval& packetTime) {
    std::time_t seconds = packetTime.tv_sec;
    std::tm utcTime{};

#ifdef _WIN32
    gmtime_s(&utcTime, &seconds);
#else
    gmtime_r(&seconds, &utcTime);
#endif

    std::ostringstream output;
    output << std::put_time(&utcTime, "%Y-%m-%dT%H:%M:%S")
           << '.' << std::setw(6) << std::setfill('0') << packetTime.tv_usec
           << 'Z';

    return output.str();
}

std::string toJsonLine(const std::string& sourceIp,
                       const std::string& destinationIp,
                       const std::string& protocol,
                       const std::string& timestamp) {
    std::ostringstream output;
    output << '{'
           << "\"sourceIp\":\"" << sourceIp << "\"," 
           << "\"destinationIp\":\"" << destinationIp << "\"," 
           << "\"protocol\":\"" << protocol << "\"," 
           << "\"timestamp\":\"" << timestamp << "\""
           << '}';
    return output.str();
}

void handlePacket(unsigned char* /*userData*/, const struct pcap_pkthdr* header, const unsigned char* packet) {
    const EthernetHeader* ethernetHeader = reinterpret_cast<const EthernetHeader*>(packet);

    // We only inspect IPv4 packets, so skip anything that is not IP.
    if (ntohs(ethernetHeader->type) != 0x0800) {
        return;
    }

    const IpHeader* ipHeader = reinterpret_cast<const IpHeader*>(packet + sizeof(EthernetHeader));

    char sourceIp[INET_ADDRSTRLEN];
    char destinationIp[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ipHeader->sourceAddress, sourceIp, sizeof(sourceIp));
    inet_ntop(AF_INET, &ipHeader->destinationAddress, destinationIp, sizeof(destinationIp));

    // Print one compact JSON object per packet so downstream tools can parse it easily.
    std::cout << toJsonLine(
        sourceIp,
        destinationIp,
        getProtocolName(ipHeader->protocol),
        formatTimestamp(header->ts)
    ) << '\n';
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <network-interface>\n";
        return 1;
    }

    char errorBuffer[PCAP_ERRBUF_SIZE];
    std::memset(errorBuffer, 0, sizeof(errorBuffer));

    // Open the selected interface in live capture mode.
    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errorBuffer);
    if (handle == nullptr) {
        std::cerr << "Failed to open interface: " << errorBuffer << '\n';
        return 1;
    }

    // Start capturing packets and print a summary for each IPv4 packet.
    pcap_loop(handle, 0, handlePacket, nullptr);

    pcap_close(handle);
    return 0;
}

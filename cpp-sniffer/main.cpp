#include <iostream>
#include <string>
#include <cstring>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <limits>
#include <cstdint>
#include <vector>
#include <atomic>
#ifndef _WIN32
#include <thread>
#endif
#include <chrono>
#include <algorithm>

#ifdef _WIN32
#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0600
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <iptypes.h>
#ifndef ERROR_BUFFER_OVERFLOW
#define ERROR_BUFFER_OVERFLOW 111L
#endif
#ifndef NO_ERROR
#define NO_ERROR 0L
#endif
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#else
#include <arpa/inet.h>
#endif

#include <pcap.h>

#if defined(_WIN32) && defined(__MINGW32__)
static int gmtime_s(std::tm* outTime, const std::time_t* inTime) {
    if (outTime == nullptr || inTime == nullptr) {
        return 1;
    }

    std::tm* temp = std::gmtime(inTime);
    if (temp == nullptr) {
        return 1;
    }

    *outTime = *temp;
    return 0;
}
#endif

std::string escapeJson(const std::string& input) {
    std::ostringstream output;
    for (char character : input) {
        switch (character) {
            case '"': output << "\\\""; break;
            case '\\': output << "\\\\"; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (static_cast<unsigned char>(character) < 0x20) {
                    output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                           << static_cast<int>(static_cast<unsigned char>(character)) << std::dec;
                } else {
                    output << character;
                }
                break;
        }
    }
    return output.str();
}

std::string formatTimestamp(const struct timeval& packetTime) {
    std::time_t seconds = packetTime.tv_sec;
    std::tm utcTime = {};

#ifdef _WIN32
    if (gmtime_s(&utcTime, &seconds) != 0) {
        return "";
    }
#else
    if (gmtime_r(&seconds, &utcTime) == nullptr) {
        return "";
    }
#endif

    std::ostringstream output;
    output << std::put_time(&utcTime, "%Y-%m-%dT%H:%M:%S")
           << '.' << std::setw(6) << std::setfill('0') << packetTime.tv_usec
           << 'Z';

    return output.str();
}

std::string encodeBase64(const unsigned char* bytes, std::size_t length) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::ostringstream output;
    for (std::size_t index = 0; index < length; index += 3) {
        const unsigned int first = bytes[index];
        const unsigned int second = index + 1 < length ? bytes[index + 1] : 0;
        const unsigned int third = index + 2 < length ? bytes[index + 2] : 0;
        const unsigned int block = (first << 16) | (second << 8) | third;
        output << alphabet[(block >> 18) & 0x3f]
               << alphabet[(block >> 12) & 0x3f]
               << (index + 1 < length ? alphabet[(block >> 6) & 0x3f] : '=')
               << (index + 2 < length ? alphabet[block & 0x3f] : '=');
    }
    return output.str();
}

std::string toJsonLine(const struct pcap_pkthdr* header, int linkType, const unsigned char* packet) {
    std::ostringstream output;
    output << '{'
           << "\"timestamp\":\"" << formatTimestamp(header->ts) << "\","
           << "\"captureLength\":" << header->caplen << ','
           << "\"originalLength\":" << header->len << ','
           << "\"linkType\":" << linkType << ','
           << "\"bytes\":\"" << encodeBase64(packet, header->caplen) << "\"}";
    return output.str();
}

std::string lowerCase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

bool containsWiFi(const char* text) {
    if (text == nullptr) {
        return false;
    }

    const std::string lowered = lowerCase(text);
    return lowered.find("wi-fi") != std::string::npos || lowered.find("wifi") != std::string::npos;
}

std::string detectInterfaceType(const std::string& description, const std::string& deviceName) {
    const std::string combined = lowerCase(description + " " + deviceName);
    if (combined.find("bluetooth") != std::string::npos) {
        return "Bluetooth";
    }
    if (combined.find("wi-fi") != std::string::npos || combined.find("wifi") != std::string::npos) {
        return "Wi-Fi";
    }
    if (combined.find("ethernet") != std::string::npos || combined.find("gbe") != std::string::npos) {
        return "Ethernet";
    }
    if (combined.find("loopback") != std::string::npos) {
        return "Loopback";
    }
    if (combined.find("virtual") != std::string::npos || combined.find("vmware") != std::string::npos) {
        return "Virtual";
    }
    return "Unknown";
}

std::string getIpAddressString(const sockaddr* address) {
    if (address == nullptr) {
        return "";
    }

    if (address->sa_family == AF_INET) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
        const auto* bytes = reinterpret_cast<const unsigned char*>(&ipv4->sin_addr);
        return std::to_string(bytes[0]) + "." + std::to_string(bytes[1]) + "." +
               std::to_string(bytes[2]) + "." + std::to_string(bytes[3]);
    }

    if (address->sa_family == AF_INET6) {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(address);
        const auto* bytes = reinterpret_cast<const unsigned char*>(&ipv6->sin6_addr);
        std::uint16_t groups[8];
        for (std::size_t index = 0; index < 8; ++index) {
            groups[index] = static_cast<std::uint16_t>((bytes[index * 2] << 8) | bytes[index * 2 + 1]);
        }

        std::size_t bestStart = 8;
        std::size_t bestLength = 1;
        for (std::size_t index = 0; index < 8;) {
            if (groups[index] != 0) {
                ++index;
                continue;
            }
            std::size_t end = index;
            while (end < 8 && groups[end] == 0) ++end;
            if (end - index > bestLength) {
                bestStart = index;
                bestLength = end - index;
            }
            index = end;
        }

        std::ostringstream output;
        for (std::size_t index = 0; index < 8;) {
            if (index == bestStart) {
                output << "::";
                index += bestLength;
                if (index == 8) break;
                continue;
            }
            const std::string current = output.str();
            if (!current.empty() && current.back() != ':') output << ':';
            output << std::hex << std::nouppercase << groups[index];
            ++index;
        }
        return output.str();
    }

    return "";
}

#ifdef _WIN32
struct WindowsAdapterMetadata {
    std::string macAddress;
    std::vector<std::string> ipAddresses;
};

WindowsAdapterMetadata getWindowsAdapterMetadata(const std::string& deviceName) {
    WindowsAdapterMetadata metadata;
    ULONG bufferLength = 15000;
    std::vector<unsigned char> buffer(bufferLength);
    ULONG result = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr,
        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &bufferLength);
    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufferLength);
        result = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &bufferLength);
    }
    if (result != NO_ERROR) return metadata;

    const std::string nativeName = lowerCase(deviceName);
    for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
         adapter != nullptr; adapter = adapter->Next) {
        const std::string adapterName = adapter->AdapterName != nullptr
            ? lowerCase(adapter->AdapterName)
            : "";
        if (adapterName.empty() || nativeName.find(adapterName) == std::string::npos) continue;

        std::ostringstream mac;
        mac << std::uppercase << std::hex << std::setfill('0');
        for (ULONG index = 0; index < adapter->PhysicalAddressLength; ++index) {
            if (index > 0) mac << ':';
            mac << std::setw(2) << static_cast<unsigned int>(adapter->PhysicalAddress[index]);
        }
        metadata.macAddress = mac.str();

        for (auto* address = adapter->FirstUnicastAddress; address != nullptr; address = address->Next) {
            const std::string ipAddress = getIpAddressString(address->Address.lpSockaddr);
            if (!ipAddress.empty() && std::find(metadata.ipAddresses.begin(), metadata.ipAddresses.end(), ipAddress) == metadata.ipAddresses.end()) {
                metadata.ipAddresses.push_back(ipAddress);
            }
        }
        break;
    }
    return metadata;
}
#endif

std::string safeInterfaceStatus(const pcap_if_t* device) {
    if (device == nullptr) {
        return "Unknown";
    }
    return ((device->flags & PCAP_IF_UP) != 0) ? "Up" : "Down";
}

int printInterfaceList() {
    char errorBuffer[PCAP_ERRBUF_SIZE];
    std::memset(errorBuffer, 0, sizeof(errorBuffer));
    pcap_if_t* devices = nullptr;
    if (pcap_findalldevs(&devices, errorBuffer) == -1) {
        std::cerr << "pcap_findalldevs failed: " << errorBuffer << '\n';
        std::cout << "[]" << std::endl;
        return 1;
    }

    std::cout << '[';
    bool first = true;

    for (pcap_if_t* device = devices; device != nullptr; device = device->next) {
        const std::string deviceName = (device->name != nullptr) ? device->name : "";
        const std::string description = (device->description != nullptr) ? device->description : "";
        const std::string friendlyName = description.empty() ? deviceName : description;
        const std::string type = detectInterfaceType(description, deviceName);
        std::vector<std::string> ipAddresses;
        std::string macAddress;
    #ifdef _WIN32
        const WindowsAdapterMetadata windowsMetadata = getWindowsAdapterMetadata(deviceName);
        macAddress = windowsMetadata.macAddress;
        ipAddresses = windowsMetadata.ipAddresses;
    #endif
        std::string status = safeInterfaceStatus(device);
        std::string captureError;
        bool captureSupported = false;

        if (!deviceName.empty()) {
            char openError[PCAP_ERRBUF_SIZE];
            std::memset(openError, 0, sizeof(openError));
            pcap_t* probe = pcap_open_live(deviceName.c_str(), 65535, 1, 1000, openError);
            if (probe != nullptr) {
                captureSupported = true;
                pcap_close(probe);
            } else {
                captureError = openError;
            }
        } else {
            captureError = "Npcap did not provide a native device identifier.";
        }

        for (pcap_addr* address = device->addresses; address != nullptr; address = address->next) {
            std::string resolved = getIpAddressString(address->addr);
            if (!resolved.empty() && std::find(ipAddresses.begin(), ipAddresses.end(), resolved) == ipAddresses.end()) {
                ipAddresses.push_back(resolved);
            }
        }

        if (!first) {
            std::cout << ',';
        }
        first = false;

        std::cout << '{'
                  << "\"name\":\"" << escapeJson(deviceName) << "\","
                  << "\"deviceId\":\"" << escapeJson(deviceName) << "\","
                  << "\"friendlyName\":\"" << escapeJson(friendlyName) << "\","
                  << "\"description\":\"" << escapeJson(description) << "\","
                  << "\"type\":\"" << escapeJson(type) << "\","
                  << "\"ipAddresses\":[";
        for (std::size_t index = 0; index < ipAddresses.size(); ++index) {
            if (index > 0) {
                std::cout << ',';
            }
            std::cout << "\"" << escapeJson(ipAddresses[index]) << "\"";
        }
        std::cout << "],"
                  << "\"macAddress\":\"" << escapeJson(macAddress) << "\","
                  << "\"status\":\"" << escapeJson(status) << "\","
                  << "\"captureSupported\":" << (captureSupported ? "true" : "false") << ','
                  << "\"captureError\":\"" << escapeJson(captureError) << "\""
                  << '}';
    }

    std::cout << ']';
    std::cout << std::endl;
    pcap_freealldevs(devices);
    return 0;
}

bool selectInterfaceAutomatically(std::string& selectedDeviceName) {
    char errorBuffer[PCAP_ERRBUF_SIZE];
    std::memset(errorBuffer, 0, sizeof(errorBuffer));

    pcap_if_t* devices = nullptr;
    if (pcap_findalldevs(&devices, errorBuffer) == -1) {
        std::cerr << "pcap_findalldevs failed: " << errorBuffer << '\n';
        return false;
    }

    pcap_if_t* firstActiveDevice = nullptr;
    pcap_if_t* preferredWiFiDevice = nullptr;

    for (pcap_if_t* device = devices; device != nullptr; device = device->next) {
        if (firstActiveDevice == nullptr && (device->flags & PCAP_IF_UP) != 0 && device->name != nullptr) {
            firstActiveDevice = device;
        }

        if (preferredWiFiDevice == nullptr && (device->flags & PCAP_IF_UP) != 0 && containsWiFi(device->description)) {
            preferredWiFiDevice = device;
        }
    }

    if (devices == nullptr) {
        std::cerr << "No network interfaces found.\n";
        pcap_freealldevs(devices);
        return false;
    }

    pcap_if_t* selectedDevice = preferredWiFiDevice != nullptr ? preferredWiFiDevice : firstActiveDevice;
    if (selectedDevice == nullptr) {
        for (pcap_if_t* device = devices; device != nullptr; device = device->next) {
            if (device->name != nullptr) {
                selectedDevice = device;
                break;
            }
        }
    }

    if (selectedDevice == nullptr || selectedDevice->name == nullptr) {
        std::cerr << "Unable to resolve selected interface.\n";
        pcap_freealldevs(devices);
        return false;
    }

    selectedDeviceName = selectedDevice->name;
    pcap_freealldevs(devices);
    return true;
}

struct CaptureContext {
    int linkType;
    std::atomic<bool>* paused;
    std::atomic<bool>* stopRequested;
};

void handlePacket(unsigned char* userData, const struct pcap_pkthdr* header, const unsigned char* packet) {
    const CaptureContext* context = reinterpret_cast<const CaptureContext*>(userData);
    if (context->paused != nullptr && context->paused->load()) {
        return;
    }
    std::cout << toJsonLine(header, context->linkType, packet) << '\n' << std::flush;
}

void readControlInput(std::atomic<bool>& paused, std::atomic<bool>& stopRequested) {
    std::string line;
    while (!stopRequested.load()) {
        if (!std::getline(std::cin, line)) {
            break;
        }

        const std::string command = line;
        if (command == "PAUSE") {
            paused.store(true);
        } else if (command == "RESUME") {
            paused.store(false);
        } else if (command == "STOP") {
            stopRequested.store(true);
            break;
        }
    }
}

#ifdef _WIN32
struct ControlThreadArguments {
    std::atomic<bool>* paused;
    std::atomic<bool>* stopRequested;
};

DWORD WINAPI readControlInputThread(LPVOID argument) {
    const auto* arguments = static_cast<ControlThreadArguments*>(argument);
    readControlInput(*arguments->paused, *arguments->stopRequested);
    return 0;
}
#endif

int main(int argc, char* argv[]) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }
#endif

    if (argc > 1 && std::string(argv[1]) == "--list-interfaces") {
        const int result = printInterfaceList();
#ifdef _WIN32
        WSACleanup();
#endif
        return result;
    }

    std::string selectedDeviceName;
    if (argc > 1 && argv[1] != nullptr && argv[1][0] != '\0' && std::string(argv[1]) != "--list-interfaces") {
        selectedDeviceName = argv[1];
    } else if (!selectInterfaceAutomatically(selectedDeviceName)) {
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    char errorBuffer[PCAP_ERRBUF_SIZE];
    std::memset(errorBuffer, 0, sizeof(errorBuffer));

    pcap_t* handle = pcap_open_live(selectedDeviceName.c_str(), 65535, 1, 1000, errorBuffer);
    if (handle == nullptr) {
        std::cerr << "Failed to open interface: " << errorBuffer << '\n';
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    const int linkType = pcap_datalink(handle);
    if (linkType < 0) {
        std::cerr << "Failed to determine capture link type: " << pcap_geterr(handle) << '\n';
        pcap_close(handle);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    std::atomic<bool> paused{false};
    std::atomic<bool> stopRequested{false};
    CaptureContext captureContext = {linkType, &paused, &stopRequested};
#ifdef _WIN32
    ControlThreadArguments controlArguments = {&paused, &stopRequested};
    HANDLE controlThread = CreateThread(nullptr, 0, readControlInputThread, &controlArguments, 0, nullptr);
    if (controlThread == nullptr) {
        std::cerr << "Failed to start capture control thread: " << GetLastError() << '\n';
        pcap_close(handle);
        WSACleanup();
        return 1;
    }
#else
    std::thread controlThread(readControlInput, std::ref(paused), std::ref(stopRequested));
#endif

    while (!stopRequested.load()) {
        if (paused.load()) {
#ifdef _WIN32
            Sleep(25);
#else
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
#endif
            continue;
        }

        int packetsSeen = pcap_dispatch(handle, 1, handlePacket, reinterpret_cast<unsigned char*>(&captureContext));
        if (packetsSeen == -1) {
            std::cerr << "Capture dispatch error: " << pcap_geterr(handle) << '\n';
            break;
        }
        if (packetsSeen == -2) {
            break;
        }
    }

#ifdef _WIN32
    WaitForSingleObject(controlThread, INFINITE);
    CloseHandle(controlThread);
#else
    if (controlThread.joinable()) {
        controlThread.join();
    }
#endif

    pcap_close(handle);

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}

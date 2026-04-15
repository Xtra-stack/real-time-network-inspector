# C++ Packet Sniffer

A small libpcap-based packet sniffer that captures live packets and prints basic IPv4 details to the console.

## Build

Linux example:

```bash
g++ main.cpp -lpcap -o sniffer
```

Windows example with Npcap/libpcap headers:

```bash
cl /EHsc main.cpp wpcap.lib Ws2_32.lib
```

## Run

```bash
./sniffer <network-interface>
```

Example:

```bash
./sniffer eth0
```

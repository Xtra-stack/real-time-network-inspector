# C++ Packet Capture

The libpcap/Npcap process captures complete link-layer frames and writes one JSON record per packet to stdout. It does not parse protocols or log payload text.

Each record contains the original libpcap timestamp, `captureLength` (`caplen`), `originalLength` (`len`), `linkType` (`pcap_datalink`), and the exact captured frame bytes in base64. The backend decoder uses the link type and frame bytes to build the normalized packet object. A shortened capture retains its smaller captured length and larger original length.

## Build

Linux example:

```bash
g++ main.cpp -lpcap -o sniffer
```

Windows example with Npcap/libpcap headers:

```bash
cl /EHsc /Fe:sniffer.exe main.cpp wpcap.lib Ws2_32.lib Iphlpapi.lib
```

Windows MinGW example with the Npcap SDK installed under `%USERPROFILE%\Downloads\npcap-sdk-1.16`:

```cmd
g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ -I "%USERPROFILE%\Downloads\npcap-sdk-1.16\Include" main.cpp "%USERPROFILE%\Downloads\npcap-sdk-1.16\Lib\wpcap.lib" -lws2_32 -liphlpapi -o sniffer-raw.exe
```

Use `sniffer-raw.exe --list-interfaces` to enumerate the provider's native device identifiers. The backend adds the installed Npcap runtime directories to the child process search path.

## Run

```bash
./sniffer <network-interface>
```

Example:

```bash
./sniffer eth0
```

When no interface argument is provided, the sniffer selects an active interface. The backend passes `SNIFFER_INTERFACE` as the argument when configured. Capture requires permission on the selected adapter. A syntax-only check is not a substitute for building and running with the real platform SDK.
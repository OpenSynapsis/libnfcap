# libnxcap - Flow-oriented Network Capture C Library

`libnxcap` is an innovative C library designed for capturing network traffic in a flow-oriented, minimalist format. It is specifically tailored for network traffic intrusion detection and analysis, providing a unified and efficient way to handle network data.

## Key Features

- **Minimalist Design**: Efficiently captures network traffic with a focus on flow-oriented data, reducing storage requirements and improving processing speed.
- **Protocol Support**: Supports TCP and UDP over both IPv4 and IPv6 protocols, ensuring compatibility with a wide range of network configurations.
- **Storage Efficiency**: Utilizes a storage-efficient format `.nxcap` based on Google's Protocol Buffers, significantly reducing the size of captured data.
- **Advanced Deduplication**: Includes mechanisms to identify and remove duplicate packets at the flow level, ensuring data quality and reducing storage needs.

## Building the Library

To build `libnxcap`, ensure you have the following dependencies installed:

- `cmake` (version 3.20 or higher)
- `protoc` (Protocol Buffers compiler, tested with version 3.21.12)
- `libpcap`
- `OpenSSL` (for secure hashing algorithms)

Run the following commands in the root directory of the project to build the library:

```bash
mkdir build
cmake -B build
make -C build
```

## Example Program: Read_files
The read_files example program demonstrates how to use libnxcap to read a .pcap file, extract flow information, and write it to a .nxcap file. This output file can be used for further analysis or processing. The program processes packets, reassembles fragmented IPv4 packets, and removes duplicate packets based on configurable time windows and packet counts at the flow level.

### Usage
Usage: read_file [OPTION]... [FILE]...
Convert a network packet capture file into NetGlyph-Capture format.

Options:
  -h, --help            Display this help and exit
  -v, --version         Output version information and exit
  -r, --read            Read a network packet capture file (.pcap|.pcapng)
  -w, --write           Write a NetGlyph-Capture file (.nxcap)
  -d, --dup-time-window Set the duplicate time window (in seconds)
  -p, --dup-packet-window Set the duplicate packet window (in packets)

## Disclaimer
This library is still in development and is not yet ready for production use. It is intended for educational and experimental purposes only. Users are encouraged to contribute to the project and report any issues or suggestions via the project's issue tracker.
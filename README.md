# *libnxcap* - Flow-oriented Network Capture *C* Library

This library provides a way to capture network traffic in a flow-oriented, minimalist format. It is designed to unify the capture of network traffic mainly for the purpose of network traffic intrusion detection and analysis.

Disclaimer: This library is still in development and is not yet ready for production use. It is intended for educational and experimental purposes only.

## Features
- Minimalist design for efficient flow-oriented capture.
- Supports TCP and UDP over IPv4 and IPv6 protocols.
- Storage efficient format `.nxcap` based on Google's Protocol Buffers.

## Building
To build the library, you need to have the following dependencies installed:
- `cmake` (version 3.20 or higher)
- `protoc` (Protocol Buffers compiler, tested with version 3.21.12)
- `libpcap`
- `OpenSSL` (for secure hashing algorithms)

To build the library, run the following commands in the root directory of the project:

```bash
mkdir build
cmake -B build
make -C build
```

An example program is provided in the `examples` directory, which demonstrates how to use the library to capture network traffic. It is built in the `bin/examples` directory.

## Read_files
This example program reads a `.pcap` file, extracts flow information, and writes it to a `.nxcap` file. The output file can be used for further analysis or processing. Packets are processed, fragmented IPv4 packets are reassembled, and duplicate packets are removed based on a configurable time window and packet count at flow level.

Here's how to run the example:

```bash
Usage: read_file [OPTION]... [FILE]...
Convert a network packet capture file into NetGlyph-Capture format.

Options:
  -h, --help     display this help and exit
  -v, --version  output version information and exit
  -r, --read     read a network packet capture file (.pcap|.pcapng)
  -w, --write    write a NetGlyph-Capture file (.nxcap)
  -d, --dup-time-window     set the duplicate time window (in seconds)
  -p, --dup-packet-window   set the duplicate packet window (in packets)
```

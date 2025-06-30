/*
 * Project: libnfcap
 * File: ipv6.h
 *
 * Description: Flow-oriented network capture library
 *
 * Copyright (C) 2025 Gabin Noblet
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * Author: Gabin Noblet 
 * Contact: <gabin.noblet@gmail.com>
 */

#ifndef IPV6_H
#define IPV6_H

#include <stdint.h>
#include <asm/byteorder.h>
#include <netinet/ip6.h>
#include <nfcap_types.h>

typedef uint32_t ipv6_addr_t[4]; // IPv6 address

typedef struct ipv6_hdr ipv6_hdr_t;
struct ipv6_hdr {
#if defined (__LITTLE_ENDIAN_BITFIELD)
    uint8_t priority:4;
    uint8_t version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    uint8_t version:4;
    uint8_t priority:4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
    uint8_t flow_lbl[3];
    uint16_t payload_len;
    uint8_t nexthdr;
    uint8_t hop_limit;
    ipv6_addr_t saddr; // Source address
    ipv6_addr_t daddr; // Destination address
} __attribute__ ((__packed__));

ipv6_hdr_t* nfcap_proto_unpack_ipv6(const u_char *packet, size_t *offset);
void nfcap_proto_ipv6_print(ipv6_addr_t ip);


#endif // IPV6_H
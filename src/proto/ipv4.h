/*
 * Project: libnfcap
 * File: ipv4.h
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

#ifndef IPV4_H
#define IPV4_H

#include <stdint.h>
#include <stdlib.h> 

#include <asm/byteorder.h>

#include <nfcap_types.h>

typedef struct ipv4_hdr ipv4_hdr_t;
struct ipv4_hdr {
#if defined (__LITTLE_ENDIAN_BITFIELD)
    uint8_t ihl:4;
    uint8_t version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    uint8_t version:4;
    uint8_t ihl:4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
    uint8_t tos; // Mutable field
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off; // Mutable field
    uint8_t ttl; // Mutable field
    uint8_t protocol;
    uint16_t check; // Mutable field
    uint32_t saddr;
    uint32_t daddr;
} __attribute__ ((__packed__));

ipv4_hdr_t* nfcap_proto_unpack_ipv4(const u_char *packet, size_t *offset);
void nfcap_proto_ipv4_print(uint32_t ip);

#endif // IPV4_H
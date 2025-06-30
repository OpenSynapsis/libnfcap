/*
 * Project: libnfcap
 * File: ipv6.c
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

#include <proto/ipv6.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

ipv6_hdr_t* nfcap_proto_unpack_ipv6(const u_char *packet, size_t *offset) {
    ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)(packet + *offset);
    *offset += sizeof(ipv6_hdr_t);
    return ipv6_hdr;
}

void nfcap_proto_ipv6_print(ipv6_addr_t ipv6) {
    uint16_t *ip = (uint16_t *)ipv6;
    // Pretty print the IPv6 address
    
    int idx0_low = -1;
    int idx0_high = -1;
    int current_idx_low = -1;
    int current_idx_high = -1;
    for (int i = 0; i < 8; i++) {
        if (ip[i] == 0) {
            if (current_idx_low == -1) {
                current_idx_low = i;
            }
            current_idx_high = i;
        } else {
            if (current_idx_low != -1) {
                if (idx0_low == -1) {
                    idx0_low = current_idx_low;
                    idx0_high = current_idx_high;
                }
                current_idx_low = -1;
                current_idx_high = -1;
            }
        }
    }

    for (int i = 0; i < 8; i++) {
        if (i == idx0_low) {
            printf(":");
            i = idx0_high;
            continue;
        } else if (i > 0) {
            printf(":");
        }
        printf("%x", ntohs(ip[i]));
    }
}
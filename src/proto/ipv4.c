/*
 * Project: nfcap
 * File: ipv4.c
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

#include <proto/ipv4.h>
#include <stdio.h>

ipv4_hdr_t* nfcap_proto_unpack_ipv4(const u_char *packet, size_t *offset) {
    ipv4_hdr_t *ipv4_hdr;
    ipv4_hdr = (ipv4_hdr_t *) (packet + *offset);

    *offset += sizeof(ipv4_hdr_t);

    return ipv4_hdr;
}

void nfcap_proto_ipv4_print(uint32_t ip) {
    printf("%u.%u.%u.%u", 
        ip & 0xFF,
        (ip >> 8) & 0xFF, 
        (ip >> 16) & 0xFF, 
        (ip >> 24) & 0xFF 
    );
}
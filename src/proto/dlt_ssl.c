/*
 * Project: nfcap
 * File: dlt_ssl.c
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

#include <proto/dlt_ssl.h>

#include <netinet/in.h>

#include <stdio.h>

dlt_ssl_hdr_t* nfcap_proto_unpack_dlt_ssl(const u_char *packet, size_t *offset) {
    dlt_ssl_hdr_t *dlt_ssl_hdr;
    dlt_ssl_hdr = (dlt_ssl_hdr_t *) (packet);// + *offset);
    
    uint8_t addr_len = ntohs(dlt_ssl_hdr->ssl_link_layer_address_length);
    *offset += DLT_SSL_STATIC_LENGTH + addr_len;

    if (addr_len > 0) {
        dlt_ssl_hdr->ssl_source_address = (uint8_t *)(packet + *offset - addr_len);
    } else {
        dlt_ssl_hdr->ssl_source_address = NULL; // No source address
    }

    dlt_ssl_hdr->ssl_protocol = *((uint16_t *)(packet + 8 + addr_len));

    return dlt_ssl_hdr;
}
    
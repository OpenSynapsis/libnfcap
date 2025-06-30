/*
 * Project: libnfcap
 * File: dlt_ssl.h
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

#ifndef DLT_SSL_H
#define DLT_SSL_H

#include <stdint.h>

#include <nfcap_types.h>

#define DLT_SSL_STATIC_LENGTH 10

typedef struct dlt_ssl_hdr dlt_ssl_hdr_t;
struct dlt_ssl_hdr {
    uint16_t ssl_packet_type;
    uint16_t ssl_link_layer_address_type;
    uint16_t ssl_link_layer_address_length;
    uint8_t *ssl_source_address;
    uint16_t _unused;
    uint16_t ssl_protocol;
} __attribute__ ((__packed__));

dlt_ssl_hdr_t* nfcap_proto_unpack_dlt_ssl(const u_char *packet, size_t *offset);

#endif // DLT_SSL_H
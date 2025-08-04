/*
 * Project: libnxcap
 * File: ip_defrag.h
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

#ifndef IP_DEFRAG_H
#define IP_DEFRAG_H

#include <core/flow_manager/hashtable.h>
#include <core/packet/packet_record.h>

#include <openssl/evp.h>

#define MF_FLAG 0x2000 // More Fragments flag in IP header
#define MF_IS_SET(flags_offset) ((flags_offset & MF_FLAG) != 0)
#define OFFSET_MASK 0x1FFF // Mask to extract the fragment offset from flags_offset
#define OFFSET_IN_BYTES(flags_offset) ((flags_offset & OFFSET_MASK) * 8) // Fragment offset in bytes
#define IS_IP_FRAGMENT(flags_offset) (MF_IS_SET(flags_offset) || (flags_offset & OFFSET_MASK) > 0)

#define NXCAP_IP_DEFRAG_CTX_BUFFER_SIZE 4096 // Default buffer size for reassembly

typedef enum {
    IP_DEFRAG_PACKET_FIRST = 0, // First fragment of the packet
    IP_DEFRAG_PACKET_MIDDLE = 1,// Middle fragment of the packet
    IP_DEFRAG_PACKET_LAST = 2,  // Last fragment of the packet
} nxcap_ip_defrag_packet_type_t;

typedef struct nxcap_ip_defrag {
    hashtable_t *ht; // Hashtable to store fragments
} nxcap_ip_defrag_t;

typedef struct nxcap_ip_defrag_key {
    uint32_t src_ip;        // Source IP address
    uint32_t dst_ip;        // Destination IP address
    uint16_t id;            // Fragment ID
    uint8_t protocol;       // Protocol (e.g., TCP, UDP)
    uint8_t _reserved;       // Reserved for future use
} nxcap_ip_defrag_key_t;

typedef struct nxcap_ip_defrag_ctx {
    nxcap_ip_defrag_key_t *key; // Key for the fragment entry
    nxcap_flow_key_t *flow_key; // Flow key associated with the fragment
    size_t total_length; // Total length of the reassembled packet

    nxcap_pkthdr_t *pkthdr;

    uint8_t *buffer;
    size_t buffer_len; // Length of the buffer for reassembly

} nxcap_ip_defrag_ctx_t;

nxcap_ip_defrag_t *nxcap_ip_defrag_create();
void nxcap_ip_defrag_destroy(nxcap_ip_defrag_t *defrag);

nxcap_ip_defrag_key_t *nxcap_ip_defrag_key_create(
    uint32_t src_ip, 
    uint32_t dst_ip, 
    uint16_t id, 
    uint8_t protocol
);

int nxcap_ip_defrag_packet_handler(
    nxcap_ip_defrag_t *defrag, 
    nxcap_ip_defrag_key_t *key,
    nxcap_flow_key_t **flow_key,
    nxcap_pkthdr_t **pkthdr,
    uint8_t *data,
    size_t data_len
);

int nxcap_ip_defrag_reassemble(
    nxcap_ip_defrag_t *defrag, 
    nxcap_ip_defrag_key_t *key
);

#endif // IP_DEFRAG_H
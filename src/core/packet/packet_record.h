/*
 * Project: libnxcap
 * File: packet_record.h
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

#ifndef PACKET_RECORD_H
#define PACKET_RECORD_H

typedef struct nxcap_pkthdr nxcap_pkthdr_t;
typedef struct nxcap_flow_manager nxcap_flow_manager_t;

#include <core/flow/flow_context.h>
#include <core/flow/flow_key.h>

#include <utils/hash.h>

#include <stdint.h>
#include <sys/time.h>
#include <pcap.h>
#include <nxcap_types.h>

struct nxcap_pkthdr {
    struct timeval ts;  // Absolute timestamp
    struct timeval rts; // Relative timestamp

    int c_state;
    int s_state;
    
    float iat;
    uint32_t plen; // Payload length
    uint8_t direction;
    uint32_t flags;

    struct {
        uint8_t is_fragment : 1; // Is this packet an IP fragment?
        uint8_t more_fragments : 1; // More fragments follow
        uint8_t reserved : 6; // Reserved bits for future use
    }__attribute__((packed));

    uint16_t frag_id; // Fragment ID for IPv4 fragments
    uint16_t frag_offset; // Fragment offset for IPv4 fragments

    uint32_t tcp_seq_num;
    packet_hash_t hash;  
    
    nxcap_pkthdr_t *next;
    nxcap_pkthdr_t *prev;
};

int nxcap_pkthdr_create(nxcap_pkthdr_t **nxcap_pkthdr, nxcap_flow_manager_t *fm, const struct pcap_pkthdr *header, const u_char* packet, nxcap_flow_key_t **_key);
int nxcap_pkthdr_update(nxcap_pkthdr_t *nxcap_pkthdr, nxcap_flow_key_t *key, nxcap_flow_context_t *flow_context);

void nxcap_pkthdr_print(nxcap_pkthdr_t *nxcap_pkthdr);

#endif // PACKET_RECORD_H
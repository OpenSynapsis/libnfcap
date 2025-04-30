/*
 * Project: nfcap
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

typedef struct nfcap_pkthdr nfcap_pkthdr_t;

#include <core/flow/flow_context.h>
#include <core/flow/flow_key.h>

#include <utils/hash.h>

#include <stdint.h>
#include <sys/time.h>
#include <pcap.h>
#include <nfcap_types.h>


struct nfcap_pkthdr {
    struct timeval ts;  // Absolute timestamp
    struct timeval rts; // Relative timestamp


    int c_state;
    int s_state;
    
    float iat;
    uint32_t plen; // Payload length
    uint8_t direction;
    uint32_t flags;

    uint32_t tcp_seq_num;
    packet_hash_t hash;  
    
    nfcap_pkthdr_t *next;
    nfcap_pkthdr_t *prev;
};

int nfcap_pkthdr_create(nfcap_pkthdr_t *nfcap_pkthdr, int datalink, const struct pcap_pkthdr *header, const u_char* packet, nfcap_flow_key_t *key);
int nfcap_pkthdr_update(nfcap_pkthdr_t *nfcap_pkthdr, nfcap_flow_key_t *key, nfcap_flow_context_t *flow_context);

void nfcap_pkthdr_print(nfcap_pkthdr_t *nfcap_pkthdr);

#endif // PACKET_RECORD_H
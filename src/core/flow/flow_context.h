/*
 * Project: nfcap
 * File: flow_context.h
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

#ifndef FLOW_CONTEXT_H
#define FLOW_CONTEXT_H

#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <core/flow/flow_key.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nfcap_flow_context nfcap_flow_context_t;

#include <core/packet/packet_record.h>

enum nfcap_flow_state {
    NFCAP_FLOW_STATE_CON_UNKNOWN = 0,
    NFCAP_FLOW_STATE_CON_CLOSED,
    NFCAP_FLOW_STATE_CON_ATTEMPT,
    NFCAP_FLOW_STATE_CON_REFUSED,
    NFCAP_FLOW_STATE_CON_ESTABLISHED,
    NFCAP_FLOW_STATE_CON_CLOSING
};
typedef enum nfcap_flow_state nfcap_flow_state_t;


struct nfcap_flow_context {
    uint32_t hash;
    nfcap_flow_key_t key;
    nfcap_flow_state_t state;
    uint8_t expired;

    struct timeval start_time;
    struct timeval pkt_last_time;

    uint32_t ip_version;
    uint32_t *ip_src;
    uint32_t *ip_dst;

    union {
        uint16_t *port_src;
        uint16_t *icmp_type;
    };

    union {
        uint16_t *port_dst;
        uint16_t *icmp_code;
    };

    uint32_t pkt_count;
    nfcap_pkthdr_t *pkt_list;
    nfcap_pkthdr_t *pkt_last;

    void *checker;

    // Used for list
    nfcap_flow_context_t *next;
    nfcap_flow_context_t *prev;

    uint32_t init_seq;
    uint32_t dup_packet_count;
};

#ifdef __cplusplus
}
#endif

int nfcap_flow_context_init(nfcap_flow_context_t *flow_context);
int nfcap_flow_context_destroy(nfcap_flow_context_t *flow_context);

int nfcap_flow_context_insert_packet(nfcap_flow_context_t *flow_context, nfcap_pkthdr_t *pkt);

size_t nfcap_flow_context_dump(nfcap_flow_context_t *flow_context, FILE* file);

int nfcap_flow_context_update_state(nfcap_flow_context_t *flow_context);

#endif // FLOW_CONTEXT_H
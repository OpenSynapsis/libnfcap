/*
 * Project: libnxcap
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

typedef struct nxcap_flow_context nxcap_flow_context_t;

#include <core/packet/packet_record.h>

enum nxcap_flow_state {
    NXCAP_FLOW_STATE_CON_UNKNOWN = 0,
    NXCAP_FLOW_STATE_CON_CLOSED,
    NXCAP_FLOW_STATE_CON_ATTEMPT,
    NXCAP_FLOW_STATE_CON_REFUSED,
    NXCAP_FLOW_STATE_CON_ESTABLISHED,
    NXCAP_FLOW_STATE_CON_CLOSING
};
typedef enum nxcap_flow_state nxcap_flow_state_t;


struct nxcap_flow_context {
    uint32_t hash;
    nxcap_flow_key_t key;
    nxcap_flow_state_t state;
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
    nxcap_pkthdr_t *pkt_list;
    nxcap_pkthdr_t *pkt_last;

    void *checker;

    // Chain flow context in creation order
    nxcap_flow_context_t *next;
    nxcap_flow_context_t *prev;

    uint32_t init_seq;
    uint32_t dup_packet_count;
};

#ifdef __cplusplus
}
#endif

int nxcap_flow_context_init(nxcap_flow_context_t *flow_context);
int nxcap_flow_context_create(nxcap_flow_context_t **flow_context, nxcap_flow_key_t *key);
int nxcap_flow_context_destroy(nxcap_flow_context_t *flow_context);

int nxcap_flow_context_insert_packet(nxcap_flow_context_t *flow_context, nxcap_pkthdr_t *pkt);

size_t nxcap_flow_context_dump(nxcap_flow_context_t *flow_context, FILE* file);

int nxcap_flow_context_update_state(nxcap_flow_context_t *flow_context);

#endif // FLOW_CONTEXT_H
/*
 * Project: libnxcap
 * File: flow_context.c
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

#include <core/flow/flow_context.h>
#include <proto/tcp.h>
#include <stdlib.h>
#include <string.h>

#include <nxcap/file.h>
#include <nxcap/protobuf/c-wrapper.h>

int nxcap_flow_context_init(nxcap_flow_context_t *flow_context) {
    memset(flow_context, 0, sizeof(nxcap_flow_context_t));
    return 0;
}

int nxcap_flow_context_create(nxcap_flow_context_t **flow_context, nxcap_flow_key_t *key) {
    *flow_context = calloc(1, sizeof(nxcap_flow_context_t));
    if (*flow_context == NULL) {
        return -1; // Memory allocation error
    }

    (*flow_context)->key = *key;

    if (key->inverted) {
        (*flow_context)->ip_src = (*flow_context)->key.ip_b;
        (*flow_context)->ip_dst = (*flow_context)->key.ip_a;
        (*flow_context)->port_src = &(*flow_context)->key.port_b;
        (*flow_context)->port_dst = &(*flow_context)->key.port_a;
    } else {
        (*flow_context)->ip_src = (*flow_context)->key.ip_a;
        (*flow_context)->ip_dst = (*flow_context)->key.ip_b;
        (*flow_context)->port_src = &(*flow_context)->key.port_a;
        (*flow_context)->port_dst = &(*flow_context)->key.port_b;
    }

    (*flow_context)->ip_version = key->ip_v;

    return 0;
}

int nxcap_flow_context_destroy(nxcap_flow_context_t *flow_context) {
    nxcap_pkthdr_t *pkt = flow_context->pkt_list;
    nxcap_pkthdr_t *next = NULL;

    while (pkt != NULL) {
        next = pkt->next;
        free(pkt);
        pkt = next;
    }

    free(flow_context);

    return 0;
}

int nxcap_flow_context_insert_packet(nxcap_flow_context_t *flow_context, nxcap_pkthdr_t *pkt) {
    if (flow_context->pkt_list == NULL) { // First packet
        flow_context->pkt_list = pkt;
        flow_context->start_time = pkt->ts;
    } else {
        // Update the last packet's next pointer
        flow_context->pkt_last->next = pkt;
        pkt->prev = flow_context->pkt_last;
    }

    flow_context->pkt_last = pkt;
    flow_context->pkt_count++;
    return 0;
}

int nxcap_flow_context_update_state(nxcap_flow_context_t *flow_context) {
    switch (flow_context->key.protocol) {
        case IPPROTO_TCP:
            tcp_connection_state_machine_t *client_sm = &((tcp_connection_checker_t *)flow_context->checker)->client_sm;
            tcp_connection_state_machine_t *server_sm = &((tcp_connection_checker_t *)flow_context->checker)->server_sm;
            if (
                client_sm->state == TCP_STATE_ESTABLISHED &&
                server_sm->state == TCP_STATE_ESTABLISHED
            ) {
                flow_context->state = NXCAP_FLOW_STATE_CON_ESTABLISHED;
            } else if (
                (client_sm->state == TCP_STATE_CLOSED || client_sm->state == TCP_STATE_TIME_WAIT || client_sm->state == TCP_STATE_LISTEN) &&
                (server_sm->state == TCP_STATE_CLOSED || server_sm->state == TCP_STATE_TIME_WAIT || server_sm->state == TCP_STATE_LISTEN)
            ) {
                flow_context->state = NXCAP_FLOW_STATE_CON_CLOSED;
            }
            break;
        default:
            break;
    }
}

size_t nxcap_flow_context_dump(nxcap_flow_context_t *flow_context, FILE* file) {
    size_t serialized_flow_context_size = 0;

    // Serialize the flow context to a file
    if (file != NULL) {
        char * serialized_flow_context;
        int ret = nxcap_protobuf_wrapper_create_flow_record(
            &serialized_flow_context,
            &serialized_flow_context_size,
            flow_context
        );
        if (ret != 0) {
            fprintf(stderr, "Failed to serialize flow context\n");
            return 0;
        }

        nxcap_file_append_record(file, serialized_flow_context, serialized_flow_context_size);

        free(serialized_flow_context);
    }

    return serialized_flow_context_size;
}

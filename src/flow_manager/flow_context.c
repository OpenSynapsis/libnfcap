/*
 * Project: nfcap
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

#include <flow_manager/flow_context.h>
#include <proto/tcp.h>
#include <stdlib.h>
#include <string.h>

#include <nfcap/file.h>
#include <nfcap/protobuf/c-wrapper.h>

int nfcap_flow_context_init(nfcap_flow_context_t *flow_context) {
    memset(flow_context, 0, sizeof(nfcap_flow_context_t));
    return 0;
}

int nfcap_flow_context_destroy(nfcap_flow_context_t *flow_context) {
    nfcap_pkthdr_t *pkt = flow_context->pkt_list;
    nfcap_pkthdr_t *next = NULL;

    while (pkt != NULL) {
        next = pkt->next;
        free(pkt);
        pkt = next;
    }

    return 0;
}

int nfcap_flow_context_insert_packet(nfcap_flow_context_t *flow_context, nfcap_pkthdr_t *pkt) {
    if (flow_context->pkt_list == NULL) { // First packet
        flow_context->pkt_list = pkt;
        flow_context->start_time = pkt->ts;
    } else {
        // Update the last packet's next pointer
        flow_context->pkt_last->next = pkt;
    }

    flow_context->pkt_last = pkt;
    flow_context->pkt_count++;
    return 0;
}

int nfcap_flow_context_update_state(nfcap_flow_context_t *flow_context) {
    switch (flow_context->key.protocol) {
        case IPPROTO_TCP:
            tcp_connection_state_machine_t *client_sm = &((tcp_connection_checker_t *)flow_context->checker)->client_sm;
            tcp_connection_state_machine_t *server_sm = &((tcp_connection_checker_t *)flow_context->checker)->server_sm;
            if (
                client_sm->state == TCP_STATE_ESTABLISHED &&
                server_sm->state == TCP_STATE_ESTABLISHED
            ) {
                flow_context->state = NFCAP_FLOW_STATE_CON_ESTABLISHED;
            } else if (
                (client_sm->state == TCP_STATE_CLOSED || client_sm->state == TCP_STATE_TIME_WAIT || client_sm->state == TCP_STATE_LISTEN) &&
                (server_sm->state == TCP_STATE_CLOSED || server_sm->state == TCP_STATE_TIME_WAIT || server_sm->state == TCP_STATE_LISTEN)
            ) {
                flow_context->state = NFCAP_FLOW_STATE_CON_CLOSED;
            }
            break;
        default:
            break;
    }
}

void nfcap_flow_context_dump(nfcap_flow_context_t *flow_context) {
    printf("Flow: ");
    nfcap_flow_key_print(&flow_context->key);
    printf("Start time: %ld.%06ld\n", flow_context->start_time.tv_sec, flow_context->start_time.tv_usec);
    printf("Packet count: %d\n", flow_context->pkt_count);

    int count = 0;
    for (nfcap_pkthdr_t *pkt = flow_context->pkt_list; pkt != NULL; pkt = pkt->next) {
        printf("\t[#%02d] ", ++count);
        nfcap_pkthdr_print(pkt);
    }

    printf("\n");

    // Serialize the flow context to a file
    // This is a placeholder for the actual serialization logic
    // In a real implementation, you would use a serialization library protobuf
    char * serialized_flow_context;
    size_t serialized_flow_context_size;
    int ret = nfcap_protobuf_wrapper_create_flow_record(
        &serialized_flow_context,
        &serialized_flow_context_size,
        flow_context
    );
    if (ret != 0) {
        fprintf(stderr, "Failed to serialize flow context\n");
        return;
    }

    FILE *file = NULL;
    if (nfcap_file_open("flow_dump.nfcap", &file, "wb") == 0) {
        nfcap_file_write(file, serialized_flow_context, serialized_flow_context_size);
        nfcap_file_close(file);
    } else {
        perror("Failed to open file");
    }

    printf("Serialized flow context size: %zu bytes\n", serialized_flow_context_size);
    free(serialized_flow_context);
}

/*
 * Project: libnfcap
 * File: duplicates.c
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

#include <modules/deduplication/duplicates.h>
#include <utils/hash.h>
#include <utils/timeval.h>
#include <string.h>

int nfcap_flow_manager_remove_duplicates(
    nfcap_flow_context_t *flow_context,
    int dup_time_window,
    int dup_packet_window
) {
    nfcap_pkthdr_t *pkt = flow_context->pkt_list;
    nfcap_pkthdr_t *prev = NULL;
    nfcap_pkthdr_t *next = NULL;

    int ret = 0;

    // Return if there are no packets
    if (pkt == NULL) {
        return 0;
    }

    // Set duplicate window to # of packets if it is 0 or if less packets than window
    if (dup_packet_window == 0 || flow_context->pkt_count < dup_packet_window) {
        dup_packet_window = flow_context->pkt_count;
    }

    // Iterate through the packet list
    uint32_t pkt_id = 0;
    uint32_t depth;
    int is_duplicate;
    struct timeval ipt = {0, 0}; // Inter packet time
    while (pkt != NULL) {
        is_duplicate = 0;

        // Check the hash of current packet against previous packets
        prev = pkt->prev;
        depth = 0;
        ret = 0;
        while (prev != NULL && is_duplicate == 0 && depth < dup_packet_window && ret == 0) {
            depth++;

            ret = timeval_subtract(&ipt, pkt->rts, prev->rts);
            if (ret < 0) {
                printf("Error: Negative inter packet time, reordering needed\n");
                continue;
            }

            if (ipt.tv_sec > 0 || (ipt.tv_sec == 0 && ipt.tv_usec > dup_time_window)) {
                // If the inter packet time is greater than 900ms, stop checking
                ret = 1;
                continue;
            }

            if (prev->hash != NULL && memcmp(prev->hash, pkt->hash, NFCAP_HASH_SIZE) == 0) {
                // Duplicate found, remove the packet
                prev->next = pkt->next;
                if (pkt->next != NULL) {
                    pkt->next->prev = prev;
                }
                is_duplicate = 1;
                flow_context->dup_packet_count++;
                flow_context->pkt_count--;
                free(pkt);
            }
            prev = prev->prev;
        }

        // Move to the next packet
        pkt_id++;
        pkt = pkt->next;
    }

    return flow_context->dup_packet_count;
}        


/*
 * Project: libnfcap
 * File: flow_manager.c
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

#include <core/flow_manager/flow_manager.h>
#include <core/flow_manager/hashtable.h>
#include <core/flow/flow_context.h>
#include <modules/ip_dedup.h>

#include <proto/ethernet.h>
#include <proto/ipv4.h>
#include <proto/tcp.h>

#include <metrics.h>

#include <stdlib.h>
#include <string.h>

#include <nfcap/file.h>

int nfcap_flow_manager_init(nfcap_flow_manager_t *flow_manager) {
    flow_manager->ht = hashtable_create(
        1 << 8, // 256 buckets
        (hashtable_equals_func_t)nfcap_flow_key_equals,
        (hashtable_hash_func_t)nfcap_flow_key_hash
    );
    flow_manager->ip_defrag = nfcap_ip_defrag_create();

    return 0;
}

int nfcap_flow_manager_destroy(nfcap_flow_manager_t *flow_manager) {
    hashtable_destroy(flow_manager->ht);

    nfcap_flow_context_t *flow_context = flow_manager->first_created_flow;
    nfcap_flow_context_t *next = NULL;
    while (flow_context != NULL) {
        next = flow_context->next;
        nfcap_flow_context_destroy(flow_context);
        flow_context = next;
    }

    nfcap_ip_defrag_destroy(flow_manager->ip_defrag);

    free(flow_manager);

    return 0;
}

static inline void nfcap_flow_manager_chain_flow(
    nfcap_flow_manager_t *flow_manager, 
    nfcap_flow_context_t *flow_context
) {
    if (flow_manager->first_created_flow == NULL) {
        flow_manager->first_created_flow = flow_context;
        flow_manager->last_created_flow = flow_context;
    } else {
        flow_manager->last_created_flow->next = flow_context;
        flow_context->prev = flow_manager->last_created_flow;
        flow_manager->last_created_flow = flow_context;
    }
}

static int nfcap_flow_manager_create_flow(
    nfcap_flow_manager_t *flow_manager, 
    nfcap_flow_context_t **flow_context, 
    nfcap_flow_key_t *key
) {
    int ret = 0;

    ret = nfcap_flow_context_create(flow_context, key);
    if (ret != 0) {
        fprintf(stderr, "[-] flow-manager: Failed to create new flow context\n");
        return ret; 
    }

    // Chain the flow context to the previous one
    nfcap_flow_manager_chain_flow(flow_manager, *flow_context);

    return 0;
}

int nfcap_flow_manager_packet_handler(
    nfcap_flow_manager_t *flow_manager, 
    const struct pcap_pkthdr *header, 
    const u_char *packet
) {
    static int count = 0;
    int ret;
    clock_t start2, end2;
    METRICS_MEASURE_CPU_TIME_INIT;

    nfcap_flow_key_t *key;
    nfcap_pkthdr_t *pkt;

    METRICS_MEASURE_CPU_TIME(
        ret = nfcap_pkthdr_create(&pkt, flow_manager, header, packet, &key),
        flow_manager->metrics.cpu_time_pkthdr_create
    );

    if (ret != 0) {
        count++;
        return FLOW_MANAGER_PROTOCOL_NOT_SUPPORTED;
    } 

    if (pkt->is_fragment) {
        count++;
        return FLOW_MANAGER_IP_FRAGMENT;
    }

    METRICS_MEASURE_CPU_TIME(
        hashtable_entry_t *entry = hashtable_get_entry(flow_manager->ht, key, sizeof(nfcap_flow_key_t)),
        flow_manager->metrics.cpu_time_hashtable_lookup
    )
    nfcap_flow_context_t *flow_context = entry->data;

    if (entry->is_occupied == false) { // Flow does not exist, create it
        ret = nfcap_flow_manager_create_flow(flow_manager, &flow_context, key);
        nfcap_proto_tcp_connection_checker_init((tcp_connection_checker_t **)&flow_context->checker);
        flow_manager->metrics.flow_count++;
        if (key->protocol == IPPROTO_TCP) {
            flow_manager->metrics.tcp_flow_count++;
        } else if (key->protocol == IPPROTO_UDP) {
            flow_manager->metrics.udp_flow_count++;
        }

        entry->is_occupied = true; // Mark the entry as occupied
        entry->key = key; // Set the key in the entry
        entry->data = flow_context; // Set the flow context in the entry
        flow_manager->ht->size++; // Increment the size of the hashtable
    }

    if (ret != 0) {
        count++;
        return ret;
    }

    METRICS_MEASURE_CPU_TIME(
        ret = nfcap_pkthdr_update(pkt, key, flow_context),
        flow_manager->metrics.cpu_time_pkthdr_update
    );
    if (ret != 0) {
        count++;
        return ret;
    }

    // Update TCP SM
    if (key->protocol == IPPROTO_TCP) {
        METRICS_MEASURE_CPU_TIME(
            ret = nfcap_proto_tcp_connection_checker_update((tcp_connection_checker_t *)flow_context->checker, pkt->flags, pkt->direction),
            flow_manager->metrics.cpu_time_pkthdr_tcp_checker
        );
        flow_manager->metrics.tcp_checker_count++;
        if (pkt->flags == TCP_SYN && flow_context->pkt_count > 0) {
            if (flow_context->init_seq != pkt->tcp_seq_num) {
                entry->is_occupied = false; // Mark the entry as unoccupied
                flow_manager->ht->size--; // Decrement the size of the hashtable

                return FLOW_MANAGER_REPASS;
            }
        }
        pkt->c_state = ((tcp_connection_checker_t *)flow_context->checker)->client_sm.state;
        pkt->s_state = ((tcp_connection_checker_t *)flow_context->checker)->server_sm.state;

        if (flow_context->pkt_count == 0) {
            flow_context->init_seq = pkt->tcp_seq_num;
        }
    }

    start2 = clock();
    nfcap_flow_context_update_state(flow_context);
    if (flow_context->state == NFCAP_FLOW_STATE_CON_CLOSED && flow_context->expired == 0) {
        flow_context->expired = 1;
        flow_manager->metrics.flow_expired++;
    }
    end2 = clock();
    
    // Insert packet in flow
    nfcap_flow_context_insert_packet(flow_context, pkt);
    
    flow_context->pkt_last_time = header->ts;
    flow_manager->packet_count++;
    flow_manager->metrics.total_payload_bytes += pkt->plen;

    if (pkt->plen > 1 << 20) { // If payload is larger than 1MB
        fprintf(stderr, "[-] Warning: Large packet detected (%u bytes) %s\n", pkt->plen, pkt->is_fragment ? "fragmented" : "not fragmented");
        // Get IP addresses string representation from ip proto version
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        if (key->ip_v == 4) {
            snprintf(src_ip, sizeof(src_ip), "%s", inet_ntoa(*(struct in_addr *)key->ip_a));
            snprintf(dst_ip, sizeof(dst_ip), "%s", inet_ntoa(*(struct in_addr *)key->ip_b));
        } else if (key->ip_v == 6) {
            inet_ntop(AF_INET6, key->ip_a, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET6, key->ip_b, dst_ip, sizeof(dst_ip));
        } else {
            snprintf(src_ip, sizeof(src_ip), "Unknown IP version %d", key->ip_v);
            snprintf(dst_ip, sizeof(dst_ip), "Unknown IP version %d", key->ip_v);
        }
        fprintf(stderr, "\t[%d] Protocol: %d, IP version: %d, Src IP: %s, Dst IP: %s\n",
            count, 
            key->protocol, 
            key->ip_v, 
            src_ip, 
            dst_ip
        );
    }

    if (key->protocol == IPPROTO_UDP) {
        flow_manager->metrics.udp_packet_count++;
    } else if (key->protocol == IPPROTO_TCP) {
        flow_manager->metrics.tcp_packet_count++;
    } else {
        flow_manager->metrics.other_packet_count++;
        //printf("Unknown protocol: %d\n", key->protocol);
    }

    flow_manager->metrics.cpu_time_total_2 += (double)(end2 - start2) / 1000; // ms
    count++;
    return 0;
}

static void nfcap_flow_manager_metrics_print(nfcap_flow_manager_t *flow_manager) {
    printf("\n### Statistics ###\n\n");

    printf("Packets: %d total, %d tcp, %d udp, %d others\n", 
        flow_manager->packet_count,
        flow_manager->metrics.tcp_packet_count,
        flow_manager->metrics.udp_packet_count,
        flow_manager->metrics.other_packet_count
    );
    printf("Bytes: %lu total, %lu payload\n", 
        flow_manager->metrics.total_bytes,
        flow_manager->metrics.total_payload_bytes
    );
    printf("Flows: %d total, %d tcp, %d udp\n", 
        flow_manager->metrics.flow_count,
        flow_manager->metrics.tcp_flow_count,
        flow_manager->metrics.udp_flow_count
    );
    printf("\n");
    
    printf("Core times: %.2fms [%.2fµs/pkt]\n", 
        flow_manager->metrics.cpu_time_total,
        (flow_manager->metrics.cpu_time_total * 1000) / flow_manager->packet_count
    );
    printf("  - pkthdr create: %.2fms [%.2f µs/pkt]\n", flow_manager->metrics.cpu_time_pkthdr_create,
        (flow_manager->metrics.cpu_time_pkthdr_create * 1000) / flow_manager->packet_count);
    printf("  - pkthdr update: %.2fms [%.2f µs/pkt]\n", flow_manager->metrics.cpu_time_pkthdr_update,
        (flow_manager->metrics.cpu_time_pkthdr_update * 1000) / flow_manager->packet_count);
    printf("  - pkthdr TCP checker: %.2fms [%.2f µs/pkt]\n", flow_manager->metrics.cpu_time_pkthdr_tcp_checker,
        (flow_manager->metrics.cpu_time_pkthdr_tcp_checker * 1000) / flow_manager->metrics.tcp_checker_count);
    printf("  - hashtable lookup: %.2fms [%.2f µs/pkt]\n", flow_manager->metrics.cpu_time_hashtable_lookup,
        (flow_manager->metrics.cpu_time_hashtable_lookup * 1000) / flow_manager->packet_count
    );

    printf("\n"); // Print hashtable metrics
    
    printf("Hashtable [%d]: %d active flows (%.1f%%), %lu probes, %lu collisions (%.1f%%)\n", 
        flow_manager->ht->capacity, 
        flow_manager->ht->size,
        (double)flow_manager->ht->size / flow_manager->ht->capacity * 100.0,
        flow_manager->ht->probe_count,
        flow_manager->ht->collision_count, 
        (double)flow_manager->ht->collision_count / (flow_manager->ht->probe_count + flow_manager->ht->collision_count) * 100.0
    );
    
    printf("\n");

    printf("IP defragmentation: %d fragments processed\n", flow_manager->ip_defrag->ht->size);

    printf("Deduplication: found %d duplicates (%.3f%%) within %d µs time window and %d pkts\n", 
        flow_manager->metrics.dup_packet_count, 
        (double)flow_manager->metrics.dup_packet_count / flow_manager->packet_count * 100.0,
        flow_manager->dup_time_window, 
        flow_manager->dup_packet_window);
    
    printf("\n");
    printf("Export: %d flows, %lu bytes written to nfcap file\n", 
        flow_manager->metrics.written_nfcap_flows, 
        flow_manager->metrics.written_nfcap_size
    );
    printf("\n");
}

int nfcap_flow_manager_dump(nfcap_flow_manager_t *flow_manager) {
    uint32_t size;

    FILE *nfcap_file = NULL;
    size_t written_bytes = 0;
    if (flow_manager->output_filename != NULL) {
        nfcap_file_create_new(flow_manager->output_filename, &nfcap_file);
    }

    nfcap_flow_context_t *flow_context = flow_manager->first_created_flow;
    int flow_count = 0;
    while (flow_context != NULL) {
        flow_manager->metrics.dup_packet_count += nfcap_flow_manager_remove_duplicates(
            flow_context, 
            flow_manager->dup_time_window, 
            flow_manager->dup_packet_window
        );
        written_bytes += nfcap_flow_context_dump(flow_context, nfcap_file);
        flow_context = flow_context->next;
        flow_count++;
    }

    if (nfcap_file != NULL) {
        flow_manager->metrics.written_nfcap_size += written_bytes;
        flow_manager->metrics.written_nfcap_flows += flow_count;
    }

    nfcap_flow_manager_metrics_print(flow_manager);

    return 0;
}
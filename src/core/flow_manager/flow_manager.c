/*
 * Project: nfcap
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
#include <core/flow/flow_context.h>
#include <modules/deduplication/duplicates.h>

#include <proto/ethernet.h>
#include <proto/ipv4.h>
#include <proto/tcp.h>

#include <metrics.h>

#include <stdlib.h>
#include <string.h>

#include <nfcap/file.h>

int nfcap_flow_manager_init(nfcap_flow_manager_t *flow_manager) {
    flow_manager->hashtable = calloc(1, sizeof(nfcap_flow_hashtable_t));
    nfcap_flow_hashtable_init(flow_manager->hashtable, 1 << 8); // 256 buckets

    flow_manager->flow_list = calloc(1, sizeof(nfcap_flow_list_t));
    nfcap_flow_list_init(flow_manager->flow_list);

    return 0;
}

int nfcap_flow_manager_destroy(nfcap_flow_manager_t *flow_manager) {
    nfcap_flow_hashtable_destroy(flow_manager->hashtable);
    free(flow_manager->hashtable);

    return 0;
}

static int nfcap_flow_manager_get_flow(
    nfcap_flow_manager_t *flow_manager, 
    nfcap_flow_context_t **flow_context, 
    nfcap_flow_key_t *key,
    double *cpu_time
) {
    int ret;
    METRICS_MEASURE_CPU_TIME_INIT;
    METRICS_MEASURE_CPU_TIME(
        ret = nfcap_flow_hashtable_get_flow(flow_manager->hashtable, flow_context, key), 
        *cpu_time
    );
    return ret;
}

static int nfcap_flow_manager_create_flow(
    nfcap_flow_manager_t *flow_manager, 
    nfcap_flow_context_t **flow_context, 
    nfcap_flow_key_t *key
) {
    METRICS_MEASURE_CPU_TIME_INIT;
    float ratio = nfcap_flow_hashtable_fill_ratio(flow_manager->hashtable);
    if (ratio > 0.90) {
        METRICS_MEASURE_CPU_TIME(
            nfcap_flow_hashtable_resize(flow_manager->hashtable),
            flow_manager->metrics.cpu_time_hashtable_resize
        )
    }

    METRICS_MEASURE_CPU_TIME(
        int ret = nfcap_flow_hashtable_insert_flow(flow_manager->hashtable, flow_context, key),
        flow_manager->metrics.cpu_time_hashtable_insert
    );

    if (ret != 0) {
        return ret;
    }
    flow_manager->metrics.hashtable_insert_count++;

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

int nfcap_flow_manager_packet_handler(
    nfcap_flow_manager_t *flow_manager, 
    const struct pcap_pkthdr *header, 
    const u_char *packet
) {
    int ret;
    clock_t start2, end2;
    METRICS_MEASURE_CPU_TIME_INIT;

    nfcap_flow_key_t key;
    nfcap_pkthdr_t *pkt = calloc(1, sizeof(nfcap_pkthdr_t));

    METRICS_MEASURE_CPU_TIME(
        ret = nfcap_pkthdr_create(pkt, flow_manager->datalink_type, header, packet, &key),
        flow_manager->metrics.cpu_time_pkthdr_create
    );

    if (ret != 0) {
        return FLOW_MANAGER_PROTOCOL_NOT_SUPPORTED;
    }

    nfcap_flow_context_t *flow_context = NULL;
    ret = nfcap_flow_manager_get_flow(flow_manager, &flow_context, &key, &flow_manager->metrics.cpu_time_hashtable_lookup);
    flow_manager->metrics.hashtable_lookup_count++;

    if (ret == FLOW_HASHTABLE_NOT_FOUND) { // Flow does not exist, create it
        ret = nfcap_flow_manager_create_flow(flow_manager, &flow_context, &key);
        nfcap_proto_tcp_connection_checker_init((tcp_connection_checker_t **)&flow_context->checker);
        flow_manager->metrics.flow_count++;
        if (key.protocol == IPPROTO_TCP) {
            flow_manager->metrics.tcp_flow_count++;
        } else if (key.protocol == IPPROTO_UDP) {
            flow_manager->metrics.udp_flow_count++;
        }
    }

    if (ret != 0) {
        return ret;
    }

    METRICS_MEASURE_CPU_TIME(
        ret = nfcap_pkthdr_update(pkt, &key, flow_context),
        flow_manager->metrics.cpu_time_pkthdr_update
    );
    if (ret != 0) {
        return ret;
    }

    // Update TCP SM
    if (key.protocol == IPPROTO_TCP) {
        METRICS_MEASURE_CPU_TIME(
            ret = nfcap_proto_tcp_connection_checker_update((tcp_connection_checker_t *)flow_context->checker, pkt->flags, pkt->direction),
            flow_manager->metrics.cpu_time_pkthdr_tcp_checker
        );
        flow_manager->metrics.tcp_checker_count++;
        if (pkt->flags == TCP_SYN && flow_context->pkt_count > 0) {
            if (flow_context->init_seq != pkt->tcp_seq_num) {
                flow_manager->metrics.dup_packet_count += nfcap_flow_manager_remove_duplicates(flow_context, flow_manager->dup_time_window, flow_manager->dup_packet_window);
                METRICS_MEASURE_CPU_TIME(
                    nfcap_flow_list_append(flow_manager->flow_list, flow_context),
                    flow_manager->metrics.cpu_time_list_insert
                );
                nfcap_flow_hashtable_remove_flow(flow_manager->hashtable, &flow_context->key);
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

    if (key.protocol == IPPROTO_UDP) {
        flow_manager->metrics.udp_packet_count++;
    } else if (key.protocol == IPPROTO_TCP) {
        flow_manager->metrics.tcp_packet_count++;
    } else {
        flow_manager->metrics.other_packet_count++;
        printf("Unknown protocol: %d\n", key.protocol);
    }

    flow_manager->metrics.cpu_time_total_2 += (double)(end2 - start2) / 1000; // ms
    return 0;
}

static void nfcap_flow_manager_metrics_print(nfcap_flow_manager_t *flow_manager) {
    printf("\n### SUMMARY ###\n\n");
    printf("Flow count: %d\n", flow_manager->metrics.flow_count);
    printf("TCP flow count: %d\n", flow_manager->metrics.tcp_flow_count);
    printf("UDP flow count: %d\n", flow_manager->metrics.udp_flow_count);
    printf("\n");

    printf("Flow expired: %d\n", flow_manager->metrics.flow_expired);
    printf("CPU time total: %.2fms [%.2fµs/pkt]\n", flow_manager->metrics.cpu_time_total,
        (flow_manager->metrics.cpu_time_total * 1000) / flow_manager->packet_count);
    printf("CPU time hashtable insert: %.2fms, [%.2f µs/ins]\n", flow_manager->metrics.cpu_time_hashtable_insert, 
        (flow_manager->metrics.cpu_time_hashtable_insert * 1000) / flow_manager->metrics.hashtable_insert_count);
    printf("CPU time hashtable lookup: %.2fms [%.2f µs/pkt]\n", flow_manager->metrics.cpu_time_hashtable_lookup,
        (flow_manager->metrics.cpu_time_hashtable_lookup * 1000) / flow_manager->packet_count);
    printf("CPU time hashtable resize: %.2fms\n", flow_manager->metrics.cpu_time_hashtable_resize);
    printf("CPU time pkthdr create: %.2fms [%.2f µs/pkt]\n", flow_manager->metrics.cpu_time_pkthdr_create,
        (flow_manager->metrics.cpu_time_pkthdr_create * 1000) / flow_manager->packet_count);
    printf("CPU time pkthdr update: %.2fms [%.2f µs/pkt]\n", flow_manager->metrics.cpu_time_pkthdr_update,
        (flow_manager->metrics.cpu_time_pkthdr_update * 1000) / flow_manager->packet_count);
    printf("CPU time pkthdr TCP checker: %.2fms [%.2f µs/pkt]\n", flow_manager->metrics.cpu_time_pkthdr_tcp_checker,
        (flow_manager->metrics.cpu_time_pkthdr_tcp_checker * 1000) / flow_manager->metrics.tcp_checker_count);

    printf("Hashtable insert count: %lu\n", flow_manager->metrics.hashtable_insert_count);
    printf("Hashtable lookup count: %lu\n", flow_manager->metrics.hashtable_lookup_count);
    printf("Hashtable insert collision count: %lu\n", flow_manager->hashtable->insert_collision_count);
    printf("Hashtable lookup collision count: %lu\n", flow_manager->hashtable->lookup_collision_count);

    printf("TCP packet count: %d\n", flow_manager->metrics.tcp_packet_count);
    printf("UDP packet count: %d\n", flow_manager->metrics.udp_packet_count);
    printf("Other packet count: %d\n", flow_manager->metrics.other_packet_count);
    
    printf("CPU time MEASURE: %.2fms [%.2fµs/pkt]\n", flow_manager->metrics.cpu_time_total_2,
        (flow_manager->metrics.cpu_time_total_2 * 1000) / flow_manager->packet_count);

    printf("\n");
    printf("Flow list size: %d\n", flow_manager->flow_list->size);
    printf("CPU time list insert: %.2fms [%.2f µs/ins]\n", flow_manager->metrics.cpu_time_list_insert,
        (flow_manager->metrics.cpu_time_list_insert * 1000) / flow_manager->flow_list->size);

    printf("Processed %d packets, found %d duplicates within %d µs time window and %d pkts\n", 
        flow_manager->packet_count, 
        flow_manager->metrics.dup_packet_count, 
        flow_manager->dup_time_window, 
        flow_manager->dup_packet_window);
    printf("Written nfcap size: %lu bytes\n", flow_manager->metrics.written_nfcap_size);
    printf("\n");
}

int export_percent_active = 0;

void
print_progress_export(size_t count, size_t max)
{
	const char suffix[] = "]";
	const size_t suffix_length = sizeof(suffix) - 1;
	
	const size_t prefix_length = 13;
    char *prefix = calloc(prefix_length + 1, sizeof(char));
    sprintf(prefix, "Export: %3d%%[", (int)(count * 100 / max));

	char *buffer = calloc(max + prefix_length + suffix_length + 1, 1); // +1 for \0
	size_t i = 0;

	strcpy(buffer, prefix);
	for (; i < max; ++i)
	{
		buffer[prefix_length + i] = i < count ? '=' : ' ';
	}
    buffer[prefix_length + count] = '>';

	strcpy(&buffer[prefix_length + i], suffix);
	printf("%s\r", buffer);

    if (count == max) {
        printf("\n");
    }

	fflush(stdout);
	free(buffer);
    free(prefix);
}

int nfcap_flow_manager_dump(nfcap_flow_manager_t *flow_manager) {
    uint32_t size;
    nfcap_flow_context_t **fc = nfcap_flow_hashtable_to_array(flow_manager->hashtable, &size);

    printf("Flow list size: %d\n", flow_manager->flow_list->size);
    printf("Flow hashtable size: %d\n", flow_manager->hashtable->capacity);
    printf("Flow hashtable count: %d\n", flow_manager->hashtable->size);

    FILE *nfcap_file = NULL;
    size_t written_bytes = 0;
    if (flow_manager->output_filename != NULL) {
        nfcap_file_create_new(flow_manager->output_filename, &nfcap_file);
    }
    
    METRICS_MEASURE_CPU_TIME_INIT;
    METRICS_MEASURE_CPU_TIME(
        for (uint32_t i = 0; i < size; i++) {
            flow_manager->metrics.dup_packet_count += nfcap_flow_manager_remove_duplicates(fc[i], flow_manager->dup_time_window, flow_manager->dup_packet_window);
            written_bytes += nfcap_flow_context_dump(fc[i], nfcap_file);
            nfcap_flow_list_append(flow_manager->flow_list, fc[i]);
            
            uint8_t percent = (100 * i) / size;
            
            if (percent > export_percent_active) {
                export_percent_active = percent;
                print_progress_export(percent / 2, 50);
            }
        },
        flow_manager->metrics.cpu_time_list_insert
    );

    flow_manager->metrics.written_nfcap_size += written_bytes;
    nfcap_flow_manager_metrics_print(flow_manager);

    return 0;
}
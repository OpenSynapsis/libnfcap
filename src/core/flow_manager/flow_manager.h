/*
 * Project: libnfcap
 * File: flow_manager.h
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

#ifndef FLOW_MANAGER_H
#define FLOW_MANAGER_H

//#define FLOW_MANAGER_SUCCESS 0
//#define FLOW_MANAGER_PROTOCOL_NOT_SUPPORTED 1
//#define FLOW_MANAGER_REPASS 2

enum {
    FLOW_MANAGER_SUCCESS = 0,
    FLOW_MANAGER_PROTOCOL_NOT_SUPPORTED,
    FLOW_MANAGER_REPASS,
    FLOW_MANAGER_IP_FRAGMENT
};

#include <stdint.h>
#include <stdio.h>
#include <pcap.h>
#include <core/flow_manager/hashtable/hashtable.h>
#include <core/packet/packet_record.h>
#include <modules/ip_defrag.h>

typedef struct nfcap_flow_manager_metrics nfcap_flow_manager_metrics_t;
struct nfcap_flow_manager_metrics {
    uint32_t flow_count;
    uint32_t udp_flow_count;
    uint32_t tcp_flow_count;

    uint32_t flow_expired;
    double cpu_time_total;
    double cpu_time_total_2;

    double cpu_time_hashtable_insert;
    uint64_t hashtable_insert_count;
    
    double cpu_time_hashtable_lookup;
    uint64_t hashtable_lookup_count;

    double cpu_time_hashtable_resize;

    double cpu_time_pkthdr_create;

    double cpu_time_pkthdr_update;

    double cpu_time_pkthdr_tcp_checker;
    uint64_t tcp_checker_count;

    double cpu_time_list_insert;

    uint32_t tcp_packet_count;
    uint32_t udp_packet_count;
    uint32_t other_packet_count;

    uint64_t total_bytes;
    uint64_t total_read_bytes;
    uint64_t total_payload_bytes;

    uint32_t dup_packet_count;
    size_t written_nfcap_size;
    uint32_t written_nfcap_flows;
};

typedef struct nfcap_flow_manager nfcap_flow_manager_t;
struct nfcap_flow_manager {
    nfcap_flow_hashtable_t *hashtable;

    nfcap_flow_context_t *first_created_flow;
    nfcap_flow_context_t *last_created_flow;

    int datalink_type;

    nfcap_ip_defrag_t *ip_defrag;

    double cpu_time_per_packet;
    uint32_t packet_count;

    nfcap_flow_manager_metrics_t metrics;
    FILE *input_file;
    char *output_filename;
    int dup_time_window;
    int dup_packet_window;
};

int nfcap_flow_manager_init(nfcap_flow_manager_t *flow_manager);
int nfcap_flow_manager_destroy(nfcap_flow_manager_t *flow_manager);

int nfcap_flow_manager_packet_handler(nfcap_flow_manager_t *flow_manager, const struct pcap_pkthdr *header, const u_char *packet);

int nfcap_flow_manager_dump(nfcap_flow_manager_t *flow_manager);

#endif // FLOW_MANAGER_H
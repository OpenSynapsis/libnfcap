/*
 * Project: NetGlyph-Probe
 * File: pcap_read.c
 *
 * Description: A software used to read network traffic into NetGlyph-Capture format (.ngcap)
 *
 * Copyright (C) 2024 Gabin Noblet
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

#include <pcap/pcap_read.h>
#include <pcap/packet_handler.h>
#include <flow_manager/flow_manager.h>
#include <nfcap_types.h>

#include <stdlib.h>

int read_pcap_file(char* filename) {
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;
    int datalink;
    int ret;

    FILE *file = fopen(filename, "rb");
    fseek(file, 0, SEEK_END);
    uint64_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    pcap = pcap_fopen_offline(file, errbuf);
    if(pcap == NULL) {
        fprintf(stderr, "Error: %s\n", errbuf);
        return -1;
    }


    datalink = pcap_datalink(pcap);
    if (datalink != DLT_EN10MB) {
        fprintf(stderr, "Error: Unsupported datalink type, type=%d\n", datalink);
        return -1;
    }

    nfcap_flow_manager_t *flow_manager = calloc(1, sizeof(nfcap_flow_manager_t));
    nfcap_flow_manager_init(flow_manager);
    flow_manager->metrics.total_bytes = file_size;
    flow_manager->input_file = file;
    
    ret = pcap_dispatch(pcap, 0, packet_handler, (u_char *) flow_manager);
    if (ret < 0) {
        fprintf(stderr, "Error: pcap_dispatch failed [%d]\n", ret);
        pcap_perror(pcap, "pcap_dispatch");
        return -1;
    }

    nfcap_flow_manager_dump(flow_manager);

    printf("Processed %d packets\n", ret);
    printf("Flow manager size: %d\n", flow_manager->hashtable->size);
    printf("Flow manager capacity: %d\n", flow_manager->hashtable->capacity);

    pcap_close(pcap);

    return 0;
}
/*
 * Project: LibNFCap
 * File: packet_handler.c
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

#include <pcap/packet_handler.h>
#include <nfcap_types.h>
#include <flow_manager/flow_key.h>
#include <flow_manager/flow_manager.h>
#include <flow_manager/mmh3.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <metrics.h>

int percent_active = 0;

void
print_progress(size_t count, size_t max)
{
	const char suffix[] = "]";
	const size_t suffix_length = sizeof(suffix) - 1;
	
	const size_t prefix_length = 19;
    char *prefix = calloc(prefix_length + 1, sizeof(char));
    sprintf(prefix, "Reading pcap: %3d%%[", (int)(count * 100 / max));

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

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    clock_t start, end;
    double cpu_time_used;
    int ret = 0;
    
    nfcap_flow_manager_t *flow_manager = (nfcap_flow_manager_t *) args;

    METRICS_MEASURE_CPU_TIME_INIT;
    
    // Measure CPU time
    METRICS_MEASURE_CPU_TIME(
        do {
            ret = nfcap_flow_manager_packet_handler(flow_manager, header, packet);
        } while (ret == FLOW_MANAGER_REPASS),
        flow_manager->metrics.cpu_time_total
    );
    
    flow_manager->metrics.total_read_bytes = ftell(flow_manager->input_file);
    double _percent = (double)flow_manager->metrics.total_read_bytes / (double)flow_manager->metrics.total_bytes;
    uint8_t percent = (100 * flow_manager->metrics.total_read_bytes) / flow_manager->metrics.total_bytes;
    
    if (percent > percent_active) {
        percent_active = percent;
        print_progress(percent / 2, 50);
    }
    

    //if (ret != 0) {
    //    fprintf(stderr, "Error: nfcap_flow_manager_packet_handler failed [%d]\n", ret);
    //}
}
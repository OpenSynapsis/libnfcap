/*
 * Project: libnxcap
 * File: parse_args.c
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


#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <config.h>
#include "parse_args.h"

static struct option long_options[] = {
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'v'},
    {"read", required_argument, 0, 'r'},
    {"write", required_argument, 0, 'w'},
    {"dup-time-window", required_argument, 0, 'd'},
    {"dup-packet-window", required_argument, 0, 'p'},
    {0, 0, 0, 0}
};

static char* short_options = "hvr:w:d:p:";

void print_usage(char *argv0) {
    printf("Usage: %s [OPTION]... [FILE]...\n", argv0);
    printf("Convert a network packet capture file into NetGlyph-Capture format.\n\n");
    printf("Options:\n");
    printf("  -h, --help     display this help and exit\n");
    printf("  -v, --version  output version information and exit\n");
    printf("  -r, --read     read a network packet capture file (.pcap|.pcapng)\n");
    printf("  -w, --write    write a NetGlyph-Capture file (.nxcap)\n");
    printf("  -d, --dup-time-window     set the duplicate time window (in seconds)\n");
    printf("  -p, --dup-packet-window     set the duplicate packet window (in packets)\n");
}

void check_mandatory_opts(struct nxcap_args *opts) {
    if(opts->input_filename == NULL) {
        fprintf(stderr, "Error: missing mandatory option --read\n");
        exit(EXIT_FAILURE);
    }
}

void print_version() {
    printf(__NGLP_NAME__);
    printf(" version ");
    printf(__NGLP_VERSION__);
    printf("\n");
}

void parse_args(int argc, char **argv, struct nxcap_args *opts) {
    int end_of_opts = 1;
    while(end_of_opts) {
        int option_index = 0;
        int c = getopt_long(argc, argv, short_options, long_options, &option_index);
        if(c == -1) {
            end_of_opts = 0;
        }
        switch(c) {
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
            case 'v':
                print_version();
                exit(EXIT_SUCCESS);
            case 'r':
                opts->input_filename = optarg;
                break;
            case 'w':
                opts->output_filename = optarg;
                break;
            case 'd':
                opts->dup_time_window = atoi(optarg);
                if(opts->dup_time_window < 0) {
                    fprintf(stderr, "Error: invalid value for --dup-time-window\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'p':
                opts->dup_packet_window = atoi(optarg);
                if(opts->dup_packet_window < 0) {
                    fprintf(stderr, "Error: invalid value for --dup-packet-window\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case '?':
                printf("\n");
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            default:
                break;
        }
    }
    check_mandatory_opts(opts);
}
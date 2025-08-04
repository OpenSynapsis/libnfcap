/*
 * Project: libnxcap
 * File: main.c
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
#include "parse_args.h"

#include <nxcap.h>

int main(int argc, char* argv[]) {
    struct nxcap_args *opts = calloc(1, sizeof(struct nxcap_args));
    parse_args(argc, argv, opts);

    read_pcap_file(opts->input_filename, opts->output_filename, opts->dup_time_window, opts->dup_packet_window);

    return 0;
}
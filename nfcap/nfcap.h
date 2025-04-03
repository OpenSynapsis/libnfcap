/*
 * Project: nfcap
 * File: nfcap.h
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

#ifndef NFCAP_H
#define NFCAP_H

#include <stdint.h>

typedef struct nfcap_flow nfcap_flow_t;
struct nfcap_flow {
    uint32_t hash;
    uint32_t count;
};

typedef struct nfcap_flow_manager nfcap_flow_manager_t;
struct nfcap_flow_manager {
    uint32_t capacity;
    uint32_t size;
    nfcap_flow_t *flows;
};

typedef struct nfcap nfcap_t;
struct nfcap {
    int version;
    int count;
};

int read_pcap_file(char* filename);

#endif // NFCAP_H
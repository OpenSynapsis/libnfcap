/*
 * Project: nfcap
 * File: flow_list.h
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

#ifndef FLOW_LIST_H
#define FLOW_LIST_H

#include <stdint.h>
#include <stdio.h>

#include <core/flow/flow_context.h>


typedef struct nfcap_flow_list nfcap_flow_list_t;
struct nfcap_flow_list {
    uint32_t size;

    nfcap_flow_context_t *head;
    nfcap_flow_context_t *tail;
    nfcap_flow_context_t *current;
};

int nfcap_flow_list_init(nfcap_flow_list_t *flow_list);
int nfcap_flow_list_destroy(nfcap_flow_list_t *flow_list);

int nfcap_flow_list_append(nfcap_flow_list_t *flow_list, nfcap_flow_context_t *flow_context);
int nfcap_flow_list_insert_sorted(nfcap_flow_list_t *flow_list, nfcap_flow_context_t *flow_context);

void nfcap_flow_list_print(nfcap_flow_list_t *flow_list);
    

#endif // FLOW_LIST_H
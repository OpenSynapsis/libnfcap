/*
 * Project: nfcap
 * File: flow_hashtable.h
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

#ifndef FLOW_HASHTABLE_H
#define FLOW_HASHTABLE_H

#include <stdbool.h>
#include <stdint.h>
#include <core/flow/flow_context.h>
#include <core/flow/flow_key.h>

#define FLOW_HASHTABLE_NOT_FOUND 1
#define FLOW_HASHTABLE_FULL 2 

typedef struct nfcap_flow_hashtable_entry nfcap_flow_hashtable_entry_t;
struct nfcap_flow_hashtable_entry {
    bool is_occupied;
    nfcap_flow_context_t *flow_context;
};

typedef struct nfcap_flow_hashtable nfcap_flow_hashtable_t;
struct nfcap_flow_hashtable {
    uint32_t size;
    uint32_t capacity;

    struct nfcap_flow_hashtable_entry *entries;

    uint64_t lookup_collision_count;
    uint64_t insert_collision_count;
};

int nfcap_flow_hashtable_init(nfcap_flow_hashtable_t *hashtable, uint32_t capacity);
int nfcap_flow_hashtable_destroy(nfcap_flow_hashtable_t *hashtable);

int nfcap_flow_hashtable_insert_flow(nfcap_flow_hashtable_t *hashtable, nfcap_flow_context_t *flow_context, nfcap_flow_key_t *key);
int nfcap_flow_hashtable_get_flow(nfcap_flow_hashtable_t *hashtable, nfcap_flow_context_t **flow_context, nfcap_flow_key_t *key);
int nfcap_flow_hashtable_remove_flow(nfcap_flow_hashtable_t *hashtable, nfcap_flow_key_t *key);

float nfcap_flow_hashtable_fill_ratio(nfcap_flow_hashtable_t *hashtable);
int nfcap_flow_hashtable_resize(nfcap_flow_hashtable_t *hashtable);

nfcap_flow_context_t **nfcap_flow_hashtable_to_array(nfcap_flow_hashtable_t *hashtable, uint32_t *size);

#endif // FLOW_HASHTABLE_H
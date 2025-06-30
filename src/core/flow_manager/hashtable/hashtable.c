/*
 * Project: libnfcap
 * File: flow_hashtable.c
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

#include <core/flow_manager/hashtable/hashtable.h>

#include <stdlib.h>
#include <string.h>

int nfcap_flow_hashtable_init(nfcap_flow_hashtable_t *hashtable, uint32_t capacity) {
    hashtable->size = 0;
    hashtable->capacity = capacity;
    hashtable->entries = calloc(capacity, sizeof(struct nfcap_flow_hashtable_entry));

    if (hashtable->entries == NULL) {
        return -1;
    }

    return 0;
}

int nfcap_flow_hashtable_destroy(nfcap_flow_hashtable_t *hashtable) {
    free(hashtable->entries);
    return 0;
}

int nfcap_flow_hashtable_insert_flow(nfcap_flow_hashtable_t *hashtable, nfcap_flow_context_t *flow_context, nfcap_flow_key_t *key) {
    int attempt = 0; 
    struct nfcap_flow_hashtable_entry *entry = NULL;

    if (hashtable->size >= hashtable->capacity) {
        return FLOW_HASHTABLE_FULL;
    }

    do {
        uint32_t hash = (key->hash + attempt) % hashtable->capacity; // Linear probing
        entry = &hashtable->entries[hash];
    } while (entry->is_occupied && ++attempt < hashtable->capacity);
    
    entry->is_occupied = true;
    entry->flow_context = flow_context;

    hashtable->size++;
    hashtable->insert_collision_count += attempt;
    return 0;
}

int nfcap_flow_hashtable_get_flow(nfcap_flow_hashtable_t *hashtable, nfcap_flow_context_t **flow_context, nfcap_flow_key_t *key) {
    int attempt = 0, ret = 0;
    struct nfcap_flow_hashtable_entry *entry = NULL;

    while (*flow_context == NULL && attempt < hashtable->capacity) {
        uint32_t hash = (key->hash + attempt) % hashtable->capacity; // Linear probing
        entry = &hashtable->entries[hash];
        
        if (entry->is_occupied && nfcap_flow_key_equals(&entry->flow_context->key, key)) {
            *flow_context = entry->flow_context;
            hashtable->lookup_collision_count += attempt;
            return 0;
        } else if (!entry->is_occupied) {
            return FLOW_HASHTABLE_NOT_FOUND;
        }
        attempt++;
    }

    return FLOW_HASHTABLE_NOT_FOUND;
}

int nfcap_flow_hashtable_remove_flow(nfcap_flow_hashtable_t *hashtable, nfcap_flow_key_t *key) {
    int attempt = 0;
    struct nfcap_flow_hashtable_entry *entry = NULL;

    while (attempt < hashtable->capacity) {
        uint32_t hash = (key->hash + attempt) % hashtable->capacity; // Linear probing
        entry = &hashtable->entries[hash];

        if (entry->is_occupied && nfcap_flow_key_equals(&entry->flow_context->key, key)) {
            entry->is_occupied = false;
            entry->flow_context = NULL;
            hashtable->size--;
            return 0;
        }
        attempt++;
    }

    return FLOW_HASHTABLE_NOT_FOUND;
}

nfcap_flow_context_t** nfcap_flow_hashtable_to_array(nfcap_flow_hashtable_t *hashtable, uint32_t *size) {
    nfcap_flow_context_t **flows = calloc(hashtable->size, sizeof(nfcap_flow_context_t *));
    if (flows == NULL) {
        return NULL;
    }

    uint32_t i = 0;
    for (uint32_t j = 0; j < hashtable->capacity; j++) {
        if (hashtable->entries[j].is_occupied) {
            flows[i++] = hashtable->entries[j].flow_context;
        }
    }

    *size = hashtable->size;
    return flows;
}

float nfcap_flow_hashtable_fill_ratio(nfcap_flow_hashtable_t *hashtable) {
    return (float) hashtable->size / (float) hashtable->capacity;
}

int nfcap_flow_hashtable_resize(nfcap_flow_hashtable_t *hashtable) {
    uint32_t new_capacity = hashtable->capacity * 2;
    struct nfcap_flow_hashtable_entry *new_entries = calloc(new_capacity, sizeof(struct nfcap_flow_hashtable_entry));
    if (new_entries == NULL) {
        return -1;
    }

    for (uint32_t i = 0; i < hashtable->capacity; i++) {
        if (hashtable->entries[i].is_occupied) {
            nfcap_flow_context_t *flow_context = hashtable->entries[i].flow_context;
            nfcap_flow_key_t *key = &flow_context->key;

            int attempt = 0;
            struct nfcap_flow_hashtable_entry *entry = NULL;

            do {
                uint32_t hash = (key->hash + attempt) % new_capacity; // Linear probing
                entry = &new_entries[hash];
            } while (entry->is_occupied && ++attempt < new_capacity);

            entry->is_occupied = true;
            entry->flow_context = flow_context;
        }
    }

    free(hashtable->entries);
    hashtable->entries = new_entries;
    hashtable->capacity = new_capacity;

    return 0;
}
/*
 * Project: nfcap
 * File: hashtable.c
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

#include <core/flow_manager/hashtable.h>
#include <stdlib.h>
#include <stdio.h>

static int hashtable_init(
    hashtable_t *hashtable, 
    uint32_t capacity, 
    hashtable_equals_func_t equals, 
    hashtable_hash_func_t hash
) {
    if (hashtable->capacity < 1) {
        hashtable->capacity = HASHTABLE_DEFAULT_CAPACITY; // Default capacity if invalid
    }

    hashtable->entries = calloc(hashtable->capacity, sizeof(hashtable_entry_t));
    hashtable->size = 0;

    if (hashtable->entries == NULL) {
        return -1; // Memory allocation failed
    }

    hashtable->lookup_collision_count = 0;
    hashtable->insert_collision_count = 0;

    hashtable->equals = equals;
    hashtable->hash = hash;

    return 0;
}

hashtable_t *hashtable_create(
    uint32_t capacity, 
    hashtable_equals_func_t equals, 
    hashtable_hash_func_t hash
) {
    hashtable_t *hashtable = calloc(1, sizeof(hashtable_t));
    if (hashtable == NULL) {
        return NULL; // Memory allocation failed
    }

    if (hashtable_init(hashtable, capacity, equals, hash) != 0) {
        free(hashtable);
        return NULL; // Initialization failed
    }

    return hashtable;
}

void hashtable_destroy(hashtable_t *hashtable) {
    for (size_t i = 0; i < hashtable->capacity; i++) {
        if (hashtable->entries[i].is_occupied) {
            free(hashtable->entries[i].key); // Free the key
        }
    }

    free(hashtable->entries);
    hashtable->size = 0;
    hashtable->capacity = 0;

    free(hashtable);
}

static int hashtable_expand(hashtable_t *hashtable);

hashtable_entry_t* hashtable_get_entry(hashtable_t *hashtable, void* key, size_t key_size) {
    if (hashtable->size >= hashtable->capacity * HASHTABLE_FILL_RATIO) {
        // Resize if filled more than the fill ratio
        if (hashtable_expand(hashtable) != 0) {
            return NULL; // Resize failed
        }
    }

    uint32_t hash = hashtable->hash(key, key_size);
    size_t index = hash % hashtable->capacity;

    while (hashtable->entries[index].is_occupied) {
        if (hashtable->equals(hashtable->entries[index].key, key)) {
            return hashtable->entries + index; // Return the found data
        }
        hashtable->lookup_collision_count++;
        index = (index + 1) % hashtable->capacity; // Linear probing
    }

    return hashtable->entries + index; // Return the empty entry for insertion
}

static int hashtable_expand(hashtable_t *hashtable) {
    size_t new_capacity = hashtable->capacity * 2;
    if (new_capacity < hashtable->capacity) { // Overflow check
        return -1; // Failed to expand, maximum capacity reached
    }
    hashtable_entry_t *new_entries = calloc(new_capacity, sizeof(hashtable_entry_t));
    if (new_entries == NULL) {
        return -1; // Memory allocation failed
    }

    for (size_t i = 0; i < hashtable->capacity; i++) {
        if (hashtable->entries[i].is_occupied) {
            uint32_t hash = hashtable->hash(hashtable->entries[i].key, hashtable->entries[i].key_size);
            size_t new_index = hash % new_capacity;

            while (new_entries[new_index].is_occupied) {
                new_index = (new_index + 1) % new_capacity; // Linear probing
            }

            new_entries[new_index] = hashtable->entries[i]; // Move the entry to the new table
        }
    }

    free(hashtable->entries); // Free old entries
    hashtable->entries = new_entries; // Point to the new entries
    hashtable->capacity = new_capacity; // Update capacity
}
/*
 * Project: libnfcap
 * File: hashtable.h
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

#ifndef HASHTABLE_H
#define HASHTABLE_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define HASHTABLE_DEFAULT_CAPACITY 16 // Default initial capacity of the hashtable
#define HASHTABLE_FILL_RATIO 0.9 // Resize when more than 90% full

typedef struct hashtable_entry {
    uint8_t is_occupied; // Indicates if the entry is occupied
    void *key;        // Pointer to the key of the entry
    size_t key_size;  // Size of the key
    void *data;       // Pointer to the data stored in the entry
} hashtable_entry_t;

typedef int (*hashtable_equals_func_t)(void *a, void *b);
typedef uint32_t (*hashtable_hash_func_t)(void *data, size_t data_size);

typedef struct hashtable {
    hashtable_entry_t *entries; // Array of entries
    uint32_t capacity;          // Total capacity of the hashtable
    uint32_t size;              // Current number of entries in the hashtable

    hashtable_equals_func_t equals; // Function to compare two entries
    hashtable_hash_func_t hash; // Function to compute the hash of an entry

    // Statistics
    uint64_t probe_count;      // Count of lookups performed
    uint64_t collision_count;   // Count of collisions during insertions
} hashtable_t;

hashtable_t *hashtable_create(uint32_t capacity, hashtable_equals_func_t equals, hashtable_hash_func_t hash);
hashtable_entry_t *hashtable_get_entry(hashtable_t *hashtable, void *key, size_t key_size);
void hashtable_destroy(hashtable_t *hashtable);

#endif // HASHTABLE_H
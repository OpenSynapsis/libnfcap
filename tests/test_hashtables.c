/*
 * Project: libnfcap
 * File: test_hashtables.c
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
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void test_hashtable_init() {
    hashtable_t *hashtable = hashtable_create(0, NULL, NULL);
    assert(hashtable != NULL); // Check if initialization was successful
   
    assert(hashtable->size == 0); // Check initial size
    assert(hashtable->capacity == HASHTABLE_DEFAULT_CAPACITY); // Check initial capacity
    assert(hashtable->entries != NULL); // Check if entries are allocated
    
    hashtable_destroy(hashtable);
}

int hashtable_equals(void *a, void *b) {
    // Simple equality check for integers
    char *str_a = (char *)a;
    char *str_b = (char *)b;
    return (strcmp(str_a, str_b) == 0); // Example equality function
}

uint32_t hashtable_hash(void *key, size_t key_size) {
    // Simple hash function for integers
    uint32_t hash = 5381;
    char *str = (char *)key;
    for (size_t i = 0; i < key_size; i++) {
        hash = ((hash << 5) + hash) + str[i]; // hash *
    }
    return hash; // Example hash function
}

void test_hashtable_get() {
    hashtable_t *hashtable = hashtable_create(0, hashtable_equals, hashtable_hash);
    assert(hashtable != NULL); // Check if initialization was successful
    
    char key1[] = "key1";
    int data1 = 42;
    hashtable_entry_t *entry = hashtable_get_entry(hashtable, &key1, sizeof(key1));
    assert(entry != NULL); // Check if entry was retrieved successfully
    entry->is_occupied = true; // Mark entry as unoccupied for testing
    entry->key = strdup(key1); // Assign key to the entry
    entry->data = &data1; // Assign data to the entry

    // Now retrieve the entry using the same key
    hashtable_entry_t *retrieved_entry = hashtable_get_entry(hashtable, &key1, sizeof(key1));
    assert(retrieved_entry != NULL); // Check if entry was

    assert(retrieved_entry->is_occupied == true); // Check if entry is occupied
    assert(strcmp((char *)retrieved_entry->key, key1) == 0); // Check if key matches
    assert(*(int *)retrieved_entry->data == data1); // Check if data matches

    // Retrieve an entry that does not exist
    char key2[] = "key2";
    hashtable_entry_t *non_existent_entry = hashtable_get_entry(hashtable, &key2, sizeof(key2));
    assert(non_existent_entry->is_occupied == false);

    hashtable_destroy(hashtable);
}

int main() {
    // Run the tests
    test_hashtable_init();
    test_hashtable_get();
 
    return 0;
}

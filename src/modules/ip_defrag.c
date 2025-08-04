/*
 * Project: libnxcap
 * File: ip_defrag.c
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

#include <modules/ip_defrag.h>
#include <proto/ipv4.h>
#include <core/packet/packet_record.h>
#include <utils/hash.h>
#include <stdio.h>  
#include <stdlib.h>
#include <string.h>

int nxcap_ip_defrag_key_equals(
    const nxcap_ip_defrag_key_t *key1, 
    const nxcap_ip_defrag_key_t *key2
) {
    return key1->src_ip == key2->src_ip &&
           key1->dst_ip == key2->dst_ip &&
           key1->id == key2->id &&
           key1->protocol == key2->protocol;
}

uint32_t nxcap_ip_defrag_key_hash(
    const nxcap_ip_defrag_key_t *key, 
    size_t key_size
) {
    // Simple hash function for the IP defragmentation key
    uint32_t hash = 5381;
    hash = ((hash << 5) + hash) + key->src_ip; // hash * 33 + src_ip
    hash = ((hash << 5) + hash) + key->dst_ip; // hash * 33 + dst_ip
    hash = ((hash << 5) + hash) + key->id;     // hash * 33 + id
    hash = ((hash << 5) + hash) + key->protocol; // hash * 33 + protocol
    return hash;
}

nxcap_ip_defrag_t *nxcap_ip_defrag_create() {
    nxcap_ip_defrag_t *defrag = calloc(1, sizeof(nxcap_ip_defrag_t));
    if (defrag == NULL) {
        return NULL; // Memory allocation failed
    }

    defrag->ht = hashtable_create(HASHTABLE_DEFAULT_CAPACITY, 
                                  (hashtable_equals_func_t)nxcap_ip_defrag_key_equals, 
                                  (hashtable_hash_func_t)nxcap_ip_defrag_key_hash);
    if (defrag->ht == NULL) {
        fprintf(stderr, "[-]Error: Failed to create hashtable for IP defragmentation.\n");
        free(defrag);
        return NULL; // Hashtable creation failed
    }

    return defrag;
}

void nxcap_ip_defrag_destroy(nxcap_ip_defrag_t *defrag) {
    if (defrag == NULL) {
        return; // Nothing to destroy
    }

    hashtable_destroy(defrag->ht);
    free(defrag);
}

nxcap_ip_defrag_key_t *nxcap_ip_defrag_key_create(
    uint32_t src_ip, 
    uint32_t dst_ip, 
    uint16_t id, 
    uint8_t protocol
) {
    nxcap_ip_defrag_key_t *key = calloc(1, sizeof(nxcap_ip_defrag_key_t));
    if (key == NULL) {
        return NULL; // Memory allocation failed
    }

    key->src_ip = src_ip;
    key->dst_ip = dst_ip;
    key->id = id;
    key->protocol = protocol;

    return key;
}

static void nxcap_ip_defrag_update_buffer(
    nxcap_ip_defrag_ctx_t *defrag_ctx, 
    const uint8_t *data, 
    size_t data_len
) {
    // Ensure the buffer is large enough to hold the new data
    if (defrag_ctx->buffer_len < defrag_ctx->total_length + data_len) {
        size_t new_size = defrag_ctx->buffer_len * 2; // Double the buffer size
        printf("Resizing buffer from %zu to %zu bytes.\n", defrag_ctx->buffer_len, new_size);
        defrag_ctx->buffer = realloc(defrag_ctx->buffer, new_size);
        if (defrag_ctx->buffer == NULL) {
            fprintf(stderr, "[-]Error: Memory allocation failed while resizing buffer.\n");
            return; // Memory allocation failed
        }
        defrag_ctx->buffer_len = new_size; // Update the buffer length
    }

    // Copy the new data into the buffer
    memcpy(defrag_ctx->buffer + defrag_ctx->total_length, data, data_len);

    defrag_ctx->total_length += data_len; // Update the total length
}

static nxcap_ip_defrag_ctx_t *nxcap_ip_defrag_ctx_create() {
    nxcap_ip_defrag_ctx_t *ctx = calloc(1, sizeof(nxcap_ip_defrag_ctx_t));
    if (ctx == NULL) {
        fprintf(stderr, "[-]Error: Memory allocation failed for IP defragmentation context.\n");
        return NULL; // Memory allocation failed
    }

    ctx->buffer = calloc(NXCAP_IP_DEFRAG_CTX_BUFFER_SIZE, sizeof(uint8_t)); // Initial buffer size of 1024 bytes
    if (ctx->buffer == NULL) {
        fprintf(stderr, "[-]Error: Memory allocation failed for buffer in IP defragmentation context.\n");
        free(ctx);
        return NULL; // Memory allocation failed
    }
    ctx->buffer_len = NXCAP_IP_DEFRAG_CTX_BUFFER_SIZE; // Set initial buffer length

    return ctx;
}

static inline void nxcap_ip_defrag_ctx_destroy(nxcap_ip_defrag_ctx_t *ctx) {
    free(ctx->buffer); // Free the buffer used for reassembly
    free(ctx); // Free the memory allocated for the key
}

int nxcap_ip_defrag_packet_handler(
    nxcap_ip_defrag_t *defrag, 
    nxcap_ip_defrag_key_t *key,
    nxcap_flow_key_t **flow_key,
    nxcap_pkthdr_t **pkthdr,
    uint8_t *data,
    size_t data_len
) {
    hashtable_entry_t *entry = hashtable_get_entry(defrag->ht, key, sizeof(nxcap_ip_defrag_key_t));

    if (!entry->is_occupied && (*pkthdr)->frag_offset == 0) { // Create a new entry for the first fragment
        nxcap_ip_defrag_ctx_t *new_defrag_ctx = nxcap_ip_defrag_ctx_create();
        if (new_defrag_ctx == NULL) {
            return -1; // Memory allocation failed
        }
        new_defrag_ctx->key = key; // Set the key for the entry
        new_defrag_ctx->flow_key = *flow_key; // Set the flow key
        new_defrag_ctx->pkthdr = *pkthdr; // Set the packet header

        // Update the buffer with the first fragment
        nxcap_ip_defrag_update_buffer(new_defrag_ctx, data, data_len);

        // Set the entry in the hashtable
        entry->key = new_defrag_ctx->key; 
        entry->data = new_defrag_ctx; 
        entry->is_occupied = true; 
        defrag->ht->size++;

    } else if (entry->is_occupied) { // Existing entry found, update the fragment
        nxcap_ip_defrag_ctx_t *defrag_ctx = (nxcap_ip_defrag_ctx_t *)entry->data;
        size_t fragment_payload_len = data_len - sizeof(ipv4_hdr_t); // Exclude the IPv4 header length

        // Update the buffer with the fragment data
        nxcap_ip_defrag_update_buffer(defrag_ctx, data + sizeof(ipv4_hdr_t), fragment_payload_len);

        free(*flow_key); // Free the created flow key
        *flow_key = defrag_ctx->flow_key; // Retrieve the flow key from the defrag context

        nxcap_pkthdr_t *retrieved_pkthdr = defrag_ctx->pkthdr;
        if (*pkthdr != NULL) {
            retrieved_pkthdr->more_fragments = (*pkthdr)->more_fragments; // Preserve the more fragments flag
            retrieved_pkthdr->frag_id = (*pkthdr)->frag_id; // Preserve
            retrieved_pkthdr->frag_offset = (*pkthdr)->frag_offset; // Preserve the fragment offset
            free(*pkthdr); // Free the existing packet header if it exists
        }
        *pkthdr = retrieved_pkthdr; // Retrieve the packet header
        (*pkthdr)->plen += fragment_payload_len; // Update the packet length
    } else { // No existing entry and not the first fragment
        // TODO: Unresolved fragment case
    }

    return 0; // Indicate that the fragment was added successfully
}

static void nxcap_ip_defrag_compute_hash(
    nxcap_ip_defrag_ctx_t *defrag_ctx
) {
    // Replace the IPv4 total length in the header with the total length of the reassembled packet
    ipv4_hdr_t *ipv4_hdr = (ipv4_hdr_t *)defrag_ctx->buffer;
    ipv4_hdr->tot_len = htons(defrag_ctx->total_length); // Update the total length in the IPv4 header

    // Compute the hash of the reassembled packet
    if (nxcap_utils_hash(defrag_ctx->buffer, 0, defrag_ctx->total_length, defrag_ctx->pkthdr->hash) != 0) {
        fprintf(stderr, "[-]Error: Failed to compute hash for reassembled packet.\n");
    }
}

int nxcap_ip_defrag_reassemble(
    nxcap_ip_defrag_t *defrag, 
    nxcap_ip_defrag_key_t *key
) {
    // Get the fragment ctx from the hashtable
    hashtable_entry_t *entry = hashtable_get_entry(defrag->ht, key, sizeof(nxcap_ip_defrag_key_t));
    
    if (!entry->is_occupied) {
        return -1; // No fragments found for the key
    }

    nxcap_ip_defrag_ctx_t *defrag_ctx = (nxcap_ip_defrag_ctx_t *)entry->data;
    
    nxcap_ip_defrag_compute_hash(defrag_ctx); // Compute the hash of the reassembled packet
    nxcap_ip_defrag_ctx_destroy(defrag_ctx); // Destroy the defrag context after reassembly

    // remove the entry from the hashtable
    entry->is_occupied = false; // Mark the entry as unoccupied
    entry->key = NULL; // Clear the key pointer
    entry->data = NULL; // Clear the data pointer
    defrag->ht->size--; // Decrease the size of the hashtable

    return 0; // Return the defrag context containing the reassembled packet
}

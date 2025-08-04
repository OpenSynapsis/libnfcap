/*
 * Project: libnxcap
 * File: hash.c
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

#include <utils/hash.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

EVP_MD_CTX *nxcap_utils_hash_init() {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        return NULL; // Memory allocation failed
    }

    if (EVP_DigestInit_ex(mdctx, NXCAP_HASH_TYPE, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return NULL; // Initialization failed
    }

    return mdctx;
}

static void _dump_buffer(const uint8_t *data, size_t len) {
    // Group the data into 16-byte chunks for better readability
    for (size_t i = 0; i < len; i += 16)
    {
        printf("%04zx: ", i); // Print the offset
        for (size_t j = 0; j < 16 && (i + j) < len; j++)
        {
            printf("%02x", data[i + j]); // Print each byte in hex
        }
        printf("\n");
    }
}

int nxcap_utils_hash_update(EVP_MD_CTX *mdctx, const uint8_t *data, size_t len) {
    //_dump_buffer(data, len); // Dump the buffer for debugging
    if (EVP_DigestUpdate(mdctx, (void *)data, len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1; // Update failed
    }
    return 0; // Update successful
}

int nxcap_utils_hash_get(EVP_MD_CTX *mdctx, packet_hash_t hash) {
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        printf("Error: Failed to finalize hash context\n");

        return -1; // Finalization failed
    }
    EVP_MD_CTX_free(mdctx);
    return 0; // Success
}

int nxcap_utils_hash(const uint8_t *data, size_t offset, size_t len, packet_hash_t hash) {
    EVP_MD_CTX *mdctx = nxcap_utils_hash_init();

    if (nxcap_utils_hash_update(mdctx, (void *)data + offset, len) != 0) {
        fprintf(stderr, "Error: Failed to update hash context\n");
        return -1;
    }

    nxcap_utils_hash_get(mdctx, hash);
    return 0; // Success
}

int nxcap_utils_hash_to_string(packet_hash_t hash, char *str) {
    memset(str, 0, NXCAP_HASH_STR_SIZE);
    for (int i = 0; i < NXCAP_HASH_SIZE; i++) {
        sprintf(str + (i * 2), "%02x", hash[i]);
    }
    return 0;
}

void nxcap_utils_hash_print(packet_hash_t hash) {
    char hash_str[NXCAP_HASH_STR_SIZE];
    nxcap_utils_hash_to_string(hash, hash_str);
    printf("Hash: %s\n", hash_str);
}
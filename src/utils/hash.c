/*
 * Project: nfcap
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

int nfcap_utils_hash(const uint8_t *data, size_t offset, size_t len, packet_hash_t hash) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        return -1;
    }

    if (EVP_DigestInit_ex(mdctx, NFCAP_HASH_TYPE, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (EVP_DigestUpdate(mdctx, (void *)data + offset, len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }
    EVP_MD_CTX_free(mdctx);
    return 0;
}

int nfcap_utils_hash_to_string(packet_hash_t hash, char *str) {
    memset(str, 0, NFCAP_HASH_STR_SIZE);
    for (int i = 0; i < NFCAP_HASH_SIZE; i++) {
        sprintf(str + (i * 2), "%02x", hash[i]);
    }
    return 0;
}
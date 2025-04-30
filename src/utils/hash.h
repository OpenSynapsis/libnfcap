/*
 * Project: nfcap
 * File: hash.h
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

#ifndef HASH_H
#define HASH_H

#include <stdint.h>
#include <stdlib.h>
#include <openssl/evp.h>

#define NFCAP_HASH_TYPE EVP_sha256()
#define NFCAP_HASH_SIZE EVP_MD_size(NFCAP_HASH_TYPE)
#define NFCAP_HASH_STR_SIZE (NFCAP_HASH_SIZE * 2 + 1) // 1 for null terminator
typedef uint8_t packet_hash_t[EVP_MAX_MD_SIZE];
int nfcap_utils_hash(const uint8_t *data, size_t offset, size_t len, packet_hash_t hash);
int nfcap_utils_hash_to_string(packet_hash_t hash, char *str);

#endif // HASH_H
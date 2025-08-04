/*
 * Project: libnxcap
 * File: file.h
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

#ifndef FILE_H
#define FILE_H

#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>

typedef struct nxcap_file_header nxcap_file_header_t;
struct nxcap_file_header {
    uint32_t magic; // RESERVED: Magic number to identify the file format 
    
    uint8_t version_major; // Major version of the file format
    uint8_t version_minor; // Minor version of the file format
    uint16_t reserved; // RESERVED: Alignment on 4 bytes

    uint32_t record_count; // Number of records in the file
    struct timeval start_time; // Start time of the capture
} __attribute__((packed));

typedef struct nxcap_file_record nxcap_file_record_t;
struct nxcap_file_record {
    uint32_t length; // Length of the record
} __attribute__((packed));

int nxcap_file_open(const char *filename, FILE **file, const char *mode);
int nxcap_file_close(FILE *file);

int nxcap_file_create_new(const char *filename, FILE **file);
int nxcap_file_append_record(FILE *file, const char *buffer, size_t size);

int nxcap_file_read(FILE *file, char *buffer, size_t size);

#endif // FILE_H
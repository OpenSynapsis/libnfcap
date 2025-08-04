/*
 * Project: libnxcap
 * File: file.c
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

#include <nxcap/file.h>

int nxcap_file_open(const char *filename, FILE **file, const char *mode) {
    *file = fopen(filename, mode);
    if (*file == NULL) {
        return -1;
    }
    return 0;
}

int nxcap_file_close(FILE *file) {
    if (file == NULL) {
        return -1;
    }
    fclose(file);
    return 0;
}

/* Create a new nxcap file with the specified filename
* and write the header to it. The file is opened in binary mode.
* Returns 0 on success, -1 on failure.
* The caller is responsible for closing the file.
*/
int nxcap_file_create_new(const char *filename, FILE **file) {
    if (nxcap_file_open(filename, file, "wb") != 0) {
        return -1;
    }
    nxcap_file_header_t header = {0};
    header.version_major = 0;
    header.version_minor = 1;
    header.reserved = 0;
    header.record_count = 0;

    if (fwrite(&header, sizeof(header), 1, *file) != 1) {
        nxcap_file_close(*file);
        return -1;
    }
    return 0;
}

int nxcap_file_append_record(FILE *file, const char *buffer, size_t size) {
    if (file == NULL || buffer == NULL) {
        return -1;
    }

    // Write the record header
    nxcap_file_record_t record_header = {0};
    record_header.length = size;
    if (fwrite(&record_header, sizeof(record_header), 1, file) != 1) {
        return -1;
    }

    size_t written = fwrite(buffer, 1, size, file);
    if (written != size) {
        return -1;
    }
    return 0;
}

int nxcap_file_read(FILE *file, char *buffer, size_t size) {
    if (file == NULL || buffer == NULL) {
        return -1;
    }
    size_t read = fread(buffer, 1, size, file);
    if (read != size) {
        return -1;
    }
    return 0;
}
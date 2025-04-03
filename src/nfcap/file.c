/*
 * Project: nfcap
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

#include <nfcap/file.h>

int nfcap_file_open(const char *filename, FILE **file, const char *mode) {
    *file = fopen(filename, mode);
    if (*file == NULL) {
        return -1;
    }
    return 0;
}

int nfcap_file_close(FILE *file) {
    if (file == NULL) {
        return -1;
    }
    fclose(file);
    return 0;
}

int nfcap_file_write(FILE *file, const char *buffer, size_t size) {
    if (file == NULL || buffer == NULL) {
        return -1;
    }
    size_t written = fwrite(buffer, 1, size, file);
    if (written != size) {
        return -1;
    }
    return 0;
}

int nfcap_file_read(FILE *file, char *buffer, size_t size) {
    if (file == NULL || buffer == NULL) {
        return -1;
    }
    size_t read = fread(buffer, 1, size, file);
    if (read != size) {
        return -1;
    }
    return 0;
}
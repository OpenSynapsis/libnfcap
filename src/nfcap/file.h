/*
 * Project: nfcap
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

int nfcap_file_open(const char *filename, FILE **file, const char *mode);
int nfcap_file_close(FILE *file);
int nfcap_file_write(FILE *file, const char *buffer, size_t size);
int nfcap_file_read(FILE *file, char *buffer, size_t size);

#endif // FILE_H
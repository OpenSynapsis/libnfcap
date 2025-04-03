/*
 * Project: nfcap
 * File: metrics.h
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

#ifndef METRICS_H
#define METRICS_H

#include <time.h>
#define METRICS_MEASURE_CPU_TIME_INIT \
    clock_t start_time, end_time; \

#define METRICS_MEASURE_CPU_TIME(code_block, metric) \
    start_time = clock(); \
    code_block; \
    end_time = clock(); \
    metric += (double)(end_time - start_time) / 1000 ; // ms \

#endif // METRICS_H
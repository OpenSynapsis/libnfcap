/*
 * Project: nfcap
 * File: wrapper.cc
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

#ifndef WRAPPER_H
#define WRAPPER_H

#include <core/flow/flow_context.h>

#ifdef __cplusplus
extern "C" {
#endif

int nfcap_protobuf_wrapper_create_flow_record(
    char **serialized_pb_flow_record,
    size_t *flow_record_size, 
    nfcap_flow_context_t *flow_context
); 

#ifdef __cplusplus
}
#endif

#endif // WRAPPER_H
/*
 * Project: nfcap
 * File: flow_list.c
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

#include <flow_manager/flow_list.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int nfcap_flow_list_init(nfcap_flow_list_t *flow_list) {
    flow_list->size = 0;
    flow_list->head = NULL;
    flow_list->tail = NULL;
    flow_list->current = NULL;

    return 0;
}

int nfcap_flow_list_destroy(nfcap_flow_list_t *flow_list) {
    nfcap_flow_context_t *flow_context = flow_list->head;
    nfcap_flow_context_t *next = NULL;

    while (flow_context != NULL) {
        next = flow_context->next;
        free(flow_context);
        flow_context = next;
    }

    return 0;
}

static nfcap_flow_context_t *nfcap_flow_context_duplicate(nfcap_flow_context_t *flow_context) {
    nfcap_flow_context_t *new_flow_context = calloc(1, sizeof(nfcap_flow_context_t));
    if (new_flow_context == NULL) {
        return NULL; // Memory allocation error
    }
    memcpy(new_flow_context, flow_context, sizeof(nfcap_flow_context_t));

    return new_flow_context;
}

int nfcap_flow_list_append(nfcap_flow_list_t *flow_list, nfcap_flow_context_t *flow_context) {
    //nfcap_flow_context_t *new_flow_context = nfcap_flow_context_duplicate(flow_context);
    //if (new_flow_context == NULL) {
    //    return -1; // Memory allocation error
    //}

    if (flow_list->head == NULL) { // First flow
        flow_list->head = flow_context;
        flow_list->tail = flow_context;
    } else {
        flow_list->tail->next = flow_context;
        flow_list->tail = flow_context;
    }

    flow_list->size++;
    return 0;
}

int nfcap_flow_list_insert_sorted(nfcap_flow_list_t *flow_list, nfcap_flow_context_t *flow_context) {
    nfcap_flow_context_t *new_flow_context = nfcap_flow_context_duplicate(flow_context);
    if (new_flow_context == NULL) {
        return -1; // Memory allocation error
    }

    if (flow_list->head == NULL || flow_context->start_time.tv_sec < flow_list->head->start_time.tv_sec) {
        flow_context->next = flow_list->head;
        flow_list->head = flow_context;
    } else {
        nfcap_flow_context_t *current = flow_list->head;
        while (current->next != NULL && current->next->start_time.tv_sec < flow_context->start_time.tv_sec) {
            current = current->next;
        }
        flow_context->next = current->next;
        current->next = flow_context;
    }

    if (flow_context->next == NULL) {
        flow_list->tail = flow_context;
    }

    flow_list->size++;
    return 0;
}
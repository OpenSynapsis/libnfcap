/*
 * Project: nfcap
 * File: flow_key.h
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

#ifndef FLOW_KEY_H
#define FLOW_KEY_H

#include <stdint.h>
#include <stdbool.h>
#include <pcap.h>
#include <nfcap_types.h>

// Spec at https://github.com/corelight/community-id-spec/blob/bda913f617389df07cdaa23606e11bbd318e265c/community-id.py#L114

typedef struct nfcap_flow_key nfcap_flow_key_t;
struct nfcap_flow_key {
    uint8_t inverted; // This defines if the key was inverted (src -> dst, dst -> src)

    uint32_t ip_v;
    uint32_t ip_a[4];
    uint32_t ip_b[4];

    uint8_t protocol;
    uint16_t port_a;
    uint16_t port_b;

    uint32_t hash; // Hash of the key, computed from the IPs, ports and protocol
};

nfcap_flow_key_t *nfcap_flow_key_init();
int nfcap_flow_key_equals(const nfcap_flow_key_t *key1, const nfcap_flow_key_t *key2);
int nfcap_flow_key_from_packet(nfcap_flow_key_t *key, const u_char *packet, size_t *offset, void **l3_hdr, void **l4_hdr);

void* nfcap_flow_key_set_ip_hdr(nfcap_flow_key_t *key, const u_char *packet, size_t *offset);
void *nfcap_flow_key_set_l4_hdr(nfcap_flow_key_t *key, const u_char *packet, size_t *offset);
void nfcap_flow_key_commit(nfcap_flow_key_t *key);

void nfcap_flow_key_hash(nfcap_flow_key_t *key);

void nfcap_flow_key_print(const nfcap_flow_key_t *key);

#endif // FLOW_KEY_H
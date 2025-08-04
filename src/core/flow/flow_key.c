/*
 * Project: libnxcap
 * File: flow_key.c
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

#include <core/flow/flow_key.h>
#include <core/flow_manager/hash/mmh3.h>
#include <stdlib.h>
#include <string.h>

#include <proto/ipv4.h>
#include <proto/ipv6.h>
#include <proto/tcp.h>
#include <proto/udp.h>

nxcap_flow_key_t *nxcap_flow_key_init() {
    return calloc(1, sizeof(nxcap_flow_key_t));
}

int nxcap_flow_key_is_ordered(const nxcap_flow_key_t *key) {
    int comp = 0;
    switch (key->ip_v) {
        case 4:
            comp = key->ip_a[0] == key->ip_b[0];
            break;
        default:
            comp = memcmp(key->ip_a, key->ip_b, sizeof(uint32_t) * 4);
            break;
    }

    return comp < 0 || (comp == 0 && key->port_a < key->port_b);
} 

int nxcap_flow_key_equals(void *a, void *b) {
    // Full equals
    nxcap_flow_key_t *key1 = (nxcap_flow_key_t *)a;
    nxcap_flow_key_t *key2 = (nxcap_flow_key_t *)b;

    bool equals = key1->ip_a[0] == key2->ip_a[0] &&
                  key1->ip_a[1] == key2->ip_a[1] &&
                  key1->ip_a[2] == key2->ip_a[2] &&
                  key1->ip_a[3] == key2->ip_a[3] &&
                  key1->ip_b[0] == key2->ip_b[0] &&
                  key1->ip_b[1] == key2->ip_b[1] &&
                  key1->ip_b[2] == key2->ip_b[2] &&
                  key1->ip_b[3] == key2->ip_b[3] &&
                  key1->port_a == key2->port_a &&
                  key1->port_b == key2->port_b &&
                  key1->protocol == key2->protocol;

    if (!equals) {
        // Cross equals (src -> dst, dst -> src)
        equals = key1->ip_a[0] == key2->ip_b[0] &&
                 key1->ip_a[1] == key2->ip_b[1] &&
                 key1->ip_a[2] == key2->ip_b[2] &&
                 key1->ip_a[3] == key2->ip_b[3] &&
                 key1->ip_b[0] == key2->ip_a[0] &&
                 key1->ip_b[1] == key2->ip_a[1] &&
                 key1->ip_b[2] == key2->ip_a[2] &&
                 key1->ip_b[3] == key2->ip_a[3] &&
                 key1->port_a == key2->port_b &&
                 key1->port_b == key2->port_a &&
                 key1->protocol == key2->protocol;
    }
    return equals;
}

static ipv4_hdr_t * nxcap_flow_key_extract_ipv4(nxcap_flow_key_t *key, const u_char *packet, size_t *offset) {
    ipv4_hdr_t *ipv4_hdr = nxcap_proto_unpack_ipv4(packet, offset);
    if (ipv4_hdr == NULL) {
        return NULL; // Error unpacking IPv4 header
    }

    key->ip_a[0] = ipv4_hdr->saddr;
    key->ip_b[0] = ipv4_hdr->daddr;
    key->protocol = ipv4_hdr->protocol;

    return ipv4_hdr;
}

static ipv6_hdr_t * nxcap_flow_key_extract_ipv6(nxcap_flow_key_t *key, const u_char *packet, size_t *offset) {
    ipv6_hdr_t *ipv6_hdr = nxcap_proto_unpack_ipv6(packet, offset);
    if (ipv6_hdr == NULL) {
        return NULL; // Error unpacking IPv6 header
    }

    memcpy(key->ip_a, &ipv6_hdr->saddr, sizeof(ipv6_addr_t));
    memcpy(key->ip_b, &ipv6_hdr->daddr, sizeof(ipv6_addr_t));
    key->protocol = ipv6_hdr->nexthdr;

    return ipv6_hdr;
}

void* nxcap_flow_key_set_ip_hdr(nxcap_flow_key_t *key, const u_char *packet, size_t *offset) {
    void *ip_hdr = NULL;

    switch (key->ip_v) {
        case 4:
            ip_hdr = (void*)nxcap_flow_key_extract_ipv4(key, packet, offset);
            break;
        case 6:
            ip_hdr = (void*)nxcap_flow_key_extract_ipv6(key, packet, offset);
            break;
        default:
            return NULL; // Unsupported IP version
    }

    return ip_hdr;
}

static tcp_hdr_t * nxcap_flow_key_extract_tcp(nxcap_flow_key_t *key, const u_char *packet, size_t *offset) {
    tcp_hdr_t *tcp_hdr = nxcap_proto_unpack_tcp(packet, offset);
    if (tcp_hdr == NULL) {
        return NULL; // Error unpacking TCP header
    }

    key->port_a = ntohs(tcp_hdr->sport);
    key->port_b = ntohs(tcp_hdr->dport);

    return tcp_hdr;
}

static udp_hdr_t * nxcap_flow_key_extract_udp(nxcap_flow_key_t *key, const u_char *packet, size_t *offset) {
    udp_hdr_t *udp_hdr = nxcap_proto_unpack_udp(packet, offset);
    if (udp_hdr == NULL) {
        return NULL; // Error unpacking UDP header
    }

    key->port_a = ntohs(udp_hdr->sport);
    key->port_b = ntohs(udp_hdr->dport);

    return udp_hdr;
}

void *nxcap_flow_key_set_l4_hdr(nxcap_flow_key_t *key, const u_char *packet, size_t *offset) {
    void *l4_hdr = NULL;

    switch (key->protocol) {
        case IPPROTO_TCP:
            l4_hdr = (void *)nxcap_flow_key_extract_tcp(key, packet, offset);
            break;
        case IPPROTO_UDP:
            l4_hdr = (void *)nxcap_flow_key_extract_udp(key, packet, offset);
            break;
        default:
            return NULL; // Unsupported protocol
    }

    return l4_hdr;
}

void nxcap_flow_key_commit(nxcap_flow_key_t *key) {
    if (nxcap_flow_key_is_ordered(key)) {
        key->inverted = 0;
    } else {
        uint32_t tmp_ip[4];
        memcpy(tmp_ip, key->ip_a, sizeof(uint32_t) * 4);
        memcpy(key->ip_a, key->ip_b, sizeof(uint32_t) * 4);
        memcpy(key->ip_b, tmp_ip, sizeof(uint32_t) * 4);

        uint16_t tmp_port = key->port_a;
        key->port_a = key->port_b;
        key->port_b = tmp_port;

        key->inverted = 1;
    }
}

int nxcap_flow_key_from_packet(nxcap_flow_key_t *key, const u_char *packet, size_t *offset, void **l3_hdr, void **l4_hdr) {
    void *ip_hdr;

    switch (key->ip_v) {
        case 4:
            ip_hdr = (void *)nxcap_proto_unpack_ipv4(packet, offset);
            *l3_hdr = ip_hdr;
            key->ip_a[0] = ((ipv4_hdr_t *)ip_hdr)->saddr;
            key->ip_b[0] = ((ipv4_hdr_t *)ip_hdr)->daddr;
            key->protocol = ((ipv4_hdr_t *)ip_hdr)->protocol;
            break;
        case 6:
            ip_hdr = (void *)nxcap_proto_unpack_ipv6(packet, offset);
            *l3_hdr = ip_hdr;
            memcpy(key->ip_a, &((ipv6_hdr_t *)ip_hdr)->saddr, sizeof(ipv6_addr_t));
            memcpy(key->ip_b, &((ipv6_hdr_t *)ip_hdr)->daddr, sizeof(ipv6_addr_t));
            key->protocol = ((ipv6_hdr_t *)ip_hdr)->nexthdr;
            break;
        default:
            return -1;
    }

    switch (key->protocol) {
        case IPPROTO_TCP:
            tcp_hdr_t *tcp_hdr = nxcap_proto_unpack_tcp(packet, offset);
            *l4_hdr = tcp_hdr;
            key->port_a = ntohs(tcp_hdr->sport);
            key->port_b = ntohs(tcp_hdr->dport);
            break;
        case IPPROTO_UDP:
            udp_hdr_t *udp_hdr = nxcap_proto_unpack_udp(packet, offset);
            *l4_hdr = udp_hdr;
            key->port_a = ntohs(udp_hdr->sport);
            key->port_b = ntohs(udp_hdr->dport);
            break;
        default:
            return -1;
    }


    if (nxcap_flow_key_is_ordered(key)) {
        key->inverted = 0;
    } else {
        uint32_t tmp_ip[4];
        memcpy(tmp_ip, key->ip_a, sizeof(uint32_t) * 4);
        memcpy(key->ip_a, key->ip_b, sizeof(uint32_t) * 4);
        memcpy(key->ip_b, tmp_ip, sizeof(uint32_t) * 4);

        uint16_t tmp_port = key->port_a;
        key->port_a = key->port_b;
        key->port_b = tmp_port;

        key->inverted = 1;
    }
    return 0;
}

static inline size_t nxcap_flow_key_buffer_append(uint8_t *buffer, const void *data, size_t len) {
    memcpy(buffer, data, len);
    return len;
}

uint32_t nxcap_flow_key_hash(nxcap_flow_key_t *key, size_t _unused) {
    (void)_unused; // Unused parameter

    uint8_t *key_bytes = calloc(1, sizeof(uint32_t) * 8 + sizeof(uint16_t) * 2 + sizeof(uint8_t));

    size_t offset = 0;
    offset += nxcap_flow_key_buffer_append(key_bytes + offset, key->ip_a, sizeof(uint32_t) * 4);
    offset += nxcap_flow_key_buffer_append(key_bytes + offset, key->ip_b, sizeof(uint32_t) * 4);
    offset += nxcap_flow_key_buffer_append(key_bytes + offset, &key->port_a, sizeof(uint16_t));
    offset += nxcap_flow_key_buffer_append(key_bytes + offset, &key->port_b, sizeof(uint16_t));
    offset += nxcap_flow_key_buffer_append(key_bytes + offset, &key->protocol, sizeof(uint8_t));

    key->hash = murmur3_32(key_bytes, offset, 0);
    //uint64_t hash64;
    //uint8_t _key = {0x01};
    //siphash(key_bytes, sizeof(uint32_t) * 8 + sizeof(uint16_t) * 2 + sizeof(uint8_t), &_key, (uint8_t *)&hash64, 8);

    free(key_bytes);
    return key->hash;
}
    
void nxcap_flow_key_print(const nxcap_flow_key_t *key) {
    if (key->inverted) {
        if (key->ip_v == 6) {
            nxcap_proto_ipv6_print((uint32_t *)key->ip_b);
            printf(":%u -> ", key->port_b);
            nxcap_proto_ipv6_print((uint32_t *)key->ip_a);
            printf(":%u (%u)\n", key->port_a, key->protocol);
            return;
        } else if (key->ip_v == 4) {
            nxcap_proto_ipv4_print(key->ip_b[0]);
            printf(":%u -> ", key->port_b);
            nxcap_proto_ipv4_print(key->ip_a[0]);
            printf(":%u (%u)\n", key->port_a, key->protocol);
        } else {
            printf("Invalid IP version: %u\n", key->ip_v);
        }
    } else {
        if (key->ip_v == 6) {
            nxcap_proto_ipv6_print((uint32_t *)key->ip_a);
            printf(":%u -> ", key->port_a);
            nxcap_proto_ipv6_print((uint32_t *)key->ip_b);
            printf(":%u (%u)\n", key->port_b, key->protocol);
            return;
        } else if (key->ip_v == 4) {
            nxcap_proto_ipv4_print(key->ip_a[0]);
            printf(":%u -> ", key->port_a);
            nxcap_proto_ipv4_print(key->ip_b[0]);
            printf(":%u (%u)\n", key->port_b, key->protocol);
        } else {
            printf("Invalid IP version: %u\n", key->ip_v);
        }
    }
    
}
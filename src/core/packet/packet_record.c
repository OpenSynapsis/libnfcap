/*
 * Project: nfcap
 * File: packet_record.c
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

#include <core/packet/packet_record.h>
#include <utils/timeval.h>
#include <utils/hash.h>

#include <proto/ethernet.h>
#include <proto/dlt_ssl.h>
#include <proto/ipv4.h>
#include <proto/ipv6.h>
#include <proto/tcp.h>

int nfcap_pkthdr_create(nfcap_pkthdr_t *nfcap_pkthdr, int datalink, const struct pcap_pkthdr *header, const u_char* packet, nfcap_flow_key_t *key) {
    size_t offset = 0;
    int ret = 0;
    uint32_t datalink_len = 0;
    
    nfcap_flow_key_init(key);

    switch (datalink) {
        case DLT_EN10MB:
            ether_hdr_t *ether_hdr = nfcap_proto_unpack_ethernet(packet, &offset);
            key->ip_v = (ntohs(ether_hdr->ether_type) == ETHERTYPE_IPV4) ? 4 : 6;
            datalink_len = offset;
            break;
        case DLT_LINUX_SLL:
            dlt_ssl_hdr_t *dlt_ssl_hdr = nfcap_proto_unpack_dlt_ssl(packet, &offset);
            key->ip_v = 4; //(ntohs(dlt_ssl_hdr->ssl_protocol) == ETHERTYPE_IPV4) ? 4 : 6;
            datalink_len = offset;
            break;
        default:
            fprintf(stderr, "Error: Unsupported datalink type, type=%d\n", datalink);
            return 1;
    }

    // Skip non-IP packets
    if (key->ip_v != 4 && key->ip_v != 6) {
        //printf("Non-IP packet, skipping\n");
        return 1;
    }

    void *ip_hdr;
    tcp_hdr_t *tcp_hdr;

    ret = nfcap_flow_key_from_packet(key, packet, &offset, (void **)&ip_hdr, (void **)&tcp_hdr);
    if (ret != 0) {
        return ret;
    }

    uint16_t ip_hdr_len;

    switch (key->ip_v) {
    case 4:
        ipv4_hdr_t *ipv4_hdr = (ipv4_hdr_t *)ip_hdr;
        ip_hdr_len = ntohs(ipv4_hdr->tot_len);

        // Set to zero mutable fields
        ipv4_hdr->tos = 0; // DSCP + ECN
        ipv4_hdr->frag_off = 0; // Flag + Fragment offset
        ipv4_hdr->ttl = 0;
        ipv4_hdr->check = 0;

        break;
    case 6:
        ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)ip_hdr;
        ip_hdr_len = sizeof(ipv6_hdr_t) + ntohs(ipv6_hdr->payload_len);

        // Set to zero mutable fields
        ipv6_hdr->priority = 0;
        ipv6_hdr->flow_lbl[0] = 0;
        ipv6_hdr->flow_lbl[1] = 0;
        ipv6_hdr->flow_lbl[2] = 0;
        ipv6_hdr->hop_limit = 0;

        break;
    default:
        return 1;
    }

    nfcap_pkthdr->ts = header->ts;
    nfcap_pkthdr->plen = (datalink_len + ip_hdr_len) - offset;
    
    // Compute the hash of the packet from network layer
    nfcap_utils_hash(packet, datalink_len, ip_hdr_len, nfcap_pkthdr->hash);
    
    if (key->protocol == IPPROTO_TCP) {
        nfcap_pkthdr->flags = tcp_hdr->flags;
        nfcap_pkthdr->tcp_seq_num = tcp_hdr->seq_num;
    }

    return 0;
}

static inline void nfcap_pkthdr_set_iat(nfcap_pkthdr_t *nfcap_pkthdr, struct timeval *iat) {
    nfcap_pkthdr->iat = timeval_to_float(iat);
}

static inline void nfcap_pkthdr_set_direction(nfcap_pkthdr_t *nfcap_pkthdr, nfcap_flow_key_t *key, nfcap_flow_context_t *flow_context) {
    nfcap_pkthdr->direction = flow_context->key.inverted ^ key->inverted;
}

int nfcap_pkthdr_update(nfcap_pkthdr_t *nfcap_pkthdr, nfcap_flow_key_t *key, nfcap_flow_context_t *flow_context) {
    struct timeval rts = {0, 0};

    if (flow_context->pkt_count != 0) { // Not the first packet, compute IAT
        int ret = timeval_subtract(&nfcap_pkthdr->rts, nfcap_pkthdr->ts, flow_context->start_time);
        if (ret < 0 || nfcap_pkthdr->rts.tv_usec < 0) {
            printf("ts = %ld.%06ld, start_time = %ld.%06ld\n", 
                nfcap_pkthdr->ts.tv_sec,
                nfcap_pkthdr->ts.tv_usec,
                flow_context->start_time.tv_sec,
                flow_context->start_time.tv_usec
            );
            return ret;
        }
    } else {
        nfcap_pkthdr->rts = rts;
    }

    //nfcap_pkthdr_set_iat(nfcap_pkthdr, &iat);
    nfcap_pkthdr_set_direction(nfcap_pkthdr, key, flow_context);

    return 0;
}

void nfcap_pkthdr_print(nfcap_pkthdr_t *nfcap_pkthdr) {
    printf("ts=%03ld.%06ld,\tdirection=%d,\tplen=%d, \tflags=%02x", 
        nfcap_pkthdr->rts.tv_sec,
        nfcap_pkthdr->rts.tv_usec,
        nfcap_pkthdr->direction,
        nfcap_pkthdr->plen,
        nfcap_pkthdr->flags
    );

    // Pretty print of client and server states
    //printf("\t");
    //printf("Client state: %s, Server state: %s", 
    //    nfcap_proto_tcp_state_to_string(nfcap_pkthdr->c_state), 
    //    nfcap_proto_tcp_state_to_string(nfcap_pkthdr->s_state)
    //);

    // Print the hash
    //char hash_str[NFCAP_HASH_STR_SIZE];
    //nfcap_utils_hash_to_string(nfcap_pkthdr->hash, hash_str);
    //printf("\tHash: %s", hash_str);
    printf("\n");
}
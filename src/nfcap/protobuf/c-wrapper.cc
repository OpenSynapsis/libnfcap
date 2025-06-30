/*
 * Project: libnfcap
 * File: c-wrapper.c
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

#include <nfcap/protobuf/c-wrapper.h>
#include "nfcap-flow.pb.h"

static inline void nfcap_protobuf_wrapper_set_l3(
    nfcap::protobuf::NFcapFlow *flow_record,
    nfcap_flow_context_t *flow_context
) {
    if (flow_context->ip_version == 4) {
        flow_record->mutable_ip()->set_src(flow_context->ip_src[0]);
        flow_record->mutable_ip()->set_dst(flow_context->ip_dst[0]);
    } else if (flow_context->ip_version == 6) {
        flow_record->mutable_ipv6()->set_src(flow_context->ip_src, 16);
        flow_record->mutable_ipv6()->set_dst(flow_context->ip_dst, 16);
    } else {
        printf("Invalid IP version: %d\n", flow_context->ip_version);
    }
}

static inline void nfcap_protobuf_wrapper_set_l4(
    nfcap::protobuf::NFcapFlow *flow_record,
    nfcap_flow_context_t *flow_context
) {
    if (flow_context->key.protocol == IPPROTO_TCP) {
        flow_record->mutable_tcp()->set_srcport(flow_context->port_src[0]);
        flow_record->mutable_tcp()->set_dstport(flow_context->port_dst[0]);
    } else if (flow_context->key.protocol == IPPROTO_UDP) {
        flow_record->mutable_udp()->set_srcport(flow_context->port_src[0]);
        flow_record->mutable_udp()->set_dstport(flow_context->port_dst[0]);
    }
}

static inline void nfcap_protobuf_wrapper_insert_packet(
    nfcap::protobuf::NFcapFlow *flow_record,
    nfcap_pkthdr_t *pkt
) {
    nfcap::protobuf::NFcapPacket *pb_pkt = flow_record->add_packets();
    pb_pkt->mutable_time()->set_seconds(pkt->rts.tv_sec);
    pb_pkt->mutable_time()->set_nanos(pkt->rts.tv_usec * 1000);

    if (pkt->direction == 0) { // Default direction is CLIENT_TO_SERVER
        pb_pkt->set_direction(nfcap::protobuf::NFcapPacketDirection::DIRECTION_CLIENT_TO_SERVER);
    } else if (pkt->direction == 1) { // Inverted direction is SERVER_TO_CLIENT
        pb_pkt->set_direction(nfcap::protobuf::NFcapPacketDirection::DIRECTION_SERVER_TO_CLIENT);

    }

    pb_pkt->set_payload_length(pkt->plen);
    pb_pkt->set_flags(pkt->flags);
}

int nfcap_protobuf_wrapper_create_flow_record(
    char **serialized_pb_flow_record,
    size_t *flow_record_size, 
    nfcap_flow_context_t *flow_context
) {
    nfcap::protobuf::NFcapFlow flow_record;

    flow_record.mutable_start_time()->set_seconds(flow_context->start_time.tv_sec);
    flow_record.mutable_start_time()->set_nanos(flow_context->start_time.tv_usec * 1000);

    nfcap_protobuf_wrapper_set_l3(&flow_record, flow_context);
    nfcap_protobuf_wrapper_set_l4(&flow_record, flow_context);

    for (nfcap_pkthdr_t *pkt = flow_context->pkt_list; pkt != NULL; pkt = pkt->next) {
        nfcap_protobuf_wrapper_insert_packet(&flow_record, pkt);
    }
    
    std::string serialized_string;

    if (!flow_record.SerializeToString(&serialized_string)) {
        return -1;
    }
    *flow_record_size = serialized_string.size();
    *serialized_pb_flow_record = (char *)calloc(1, *flow_record_size);
    memcpy(*serialized_pb_flow_record, serialized_string.c_str(), *flow_record_size);

    return 0;
}
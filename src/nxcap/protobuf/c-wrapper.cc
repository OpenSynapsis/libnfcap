/*
 * Project: libnxcap
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

#include <nxcap/protobuf/c-wrapper.h>
#include "nxcap-flow.pb.h"

static inline void nxcap_protobuf_wrapper_set_l3(
    nxcap::protobuf::NXcapFlow *flow_record,
    nxcap_flow_context_t *flow_context
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

static inline void nxcap_protobuf_wrapper_set_l4(
    nxcap::protobuf::NXcapFlow *flow_record,
    nxcap_flow_context_t *flow_context
) {
    if (flow_context->key.protocol == IPPROTO_TCP) {
        flow_record->mutable_tcp()->set_srcport(flow_context->port_src[0]);
        flow_record->mutable_tcp()->set_dstport(flow_context->port_dst[0]);
    } else if (flow_context->key.protocol == IPPROTO_UDP) {
        flow_record->mutable_udp()->set_srcport(flow_context->port_src[0]);
        flow_record->mutable_udp()->set_dstport(flow_context->port_dst[0]);
    }
}

static inline void nxcap_protobuf_wrapper_insert_packet(
    nxcap::protobuf::NXcapFlow *flow_record,
    nxcap_pkthdr_t *pkt
) {
    nxcap::protobuf::NXcapPacket *pb_pkt = flow_record->add_packets();
    pb_pkt->mutable_time()->set_seconds(pkt->rts.tv_sec);
    pb_pkt->mutable_time()->set_nanos(pkt->rts.tv_usec * 1000);

    if (pkt->direction == 0) { // Default direction is CLIENT_TO_SERVER
        pb_pkt->set_direction(nxcap::protobuf::NXcapPacketDirection::DIRECTION_CLIENT_TO_SERVER);
    } else if (pkt->direction == 1) { // Inverted direction is SERVER_TO_CLIENT
        pb_pkt->set_direction(nxcap::protobuf::NXcapPacketDirection::DIRECTION_SERVER_TO_CLIENT);

    }

    pb_pkt->set_payload_length(pkt->plen);
    pb_pkt->set_flags(pkt->flags);
}

int nxcap_protobuf_wrapper_create_flow_record(
    char **serialized_pb_flow_record,
    size_t *flow_record_size, 
    nxcap_flow_context_t *flow_context
) {
    nxcap::protobuf::NXcapFlow flow_record;

    flow_record.mutable_start_time()->set_seconds(flow_context->start_time.tv_sec);
    flow_record.mutable_start_time()->set_nanos(flow_context->start_time.tv_usec * 1000);

    nxcap_protobuf_wrapper_set_l3(&flow_record, flow_context);
    nxcap_protobuf_wrapper_set_l4(&flow_record, flow_context);

    for (nxcap_pkthdr_t *pkt = flow_context->pkt_list; pkt != NULL; pkt = pkt->next) {
        nxcap_protobuf_wrapper_insert_packet(&flow_record, pkt);
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
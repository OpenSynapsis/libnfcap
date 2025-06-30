/*
 * Project: libnfcap
 * File: tcp.h
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

#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include <stdlib.h>
#include <asm/byteorder.h>

#include <nfcap_types.h>

typedef struct tcp_hdr tcp_hdr_t;
struct tcp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq_num;
    uint32_t ack_num;
#if defined (__LITTLE_ENDIAN_BITFIELD)
    uint8_t reserved:4;
    uint8_t data_offset:4;
    union {
        uint8_t flags;
        struct {
            uint8_t fin:1;
            uint8_t syn:1;
            uint8_t rst:1;
            uint8_t psh:1;
            uint8_t ack:1;
            uint8_t urg:1;
            uint8_t ece:1;
            uint8_t cwr:1;
        };
    };
#elif defined (__BIG_ENDIAN_BITFIELD)
    uint8_t data_offset:4;
    uint8_t reserved:4;
    union {
        uint8_t flags;
        struct {
            uint8_t cwr:1;
            uint8_t ece:1;
            uint8_t urg:1;
            uint8_t ack:1;
            uint8_t psh:1;
            uint8_t rst:1;
            uint8_t syn:1;
            uint8_t fin:1;
        };
    };
#else
#error "Please fix <asm/byteorder.h>"
#endif
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
} __attribute__ ((__packed__));

tcp_hdr_t* nfcap_proto_unpack_tcp(const u_char *packet, size_t *offset);

enum {
    TCP_STATE_MACHINE_SUCCESS = 0,
    TCP_STATE_MACHINE_ERROR = 1,
    TCP_STATE_MACHINE_ALREADY_ESTABLISHED = 2,   
    TCP_STATE_MACHINE_SYN = 3,
};

enum {
    TCP_FIN = 0x01,
    TCP_SYN = 0x02,
    TCP_RST = 0x04,
    TCP_PSH = 0x08,
    TCP_ACK = 0x10,
    TCP_URG = 0x20,
    TCP_ECE = 0x40,
    TCP_CWR = 0x80
};

typedef enum tcp_connection_state tcp_connection_state_t;
enum tcp_connection_state {
    TCP_STATE_CLOSED = 0,
    TCP_STATE_LISTEN,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECEIVED,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_CLOSING,
    TCP_STATE_LAST_ACK,
    TCP_STATE_TIME_WAIT
};

char* nfcap_proto_tcp_state_to_string(tcp_connection_state_t state);

typedef struct tcp_connection_state_machine tcp_connection_state_machine_t;
struct tcp_connection_state_machine {
    tcp_connection_state_t state;
    uint32_t seq_num;
    uint32_t ack_num;
};

int nfcap_proto_tcp_state_machine_send(
    tcp_connection_state_machine_t *state_machine,
    uint8_t flags,
    tcp_connection_state_t peer_state
);

int nfcap_proto_tcp_state_machine_recv(
    tcp_connection_state_machine_t *state_machine,
    uint8_t flags,
    tcp_connection_state_t peer_state
);

typedef struct tcp_connection_checker tcp_connection_checker_t;
struct tcp_connection_checker {
    tcp_connection_state_machine_t client_sm;
    tcp_connection_state_machine_t server_sm;
};

int nfcap_proto_tcp_connection_checker_init(tcp_connection_checker_t **checker);
int nfcap_proto_tcp_connection_checker_update(
    tcp_connection_checker_t *checker,
    uint8_t flags,
    uint8_t direction
);


#endif // TCP_H
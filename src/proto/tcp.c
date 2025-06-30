/*
 * Project: libnfcap
 * File: tcp.c
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

#include <proto/tcp.h>

tcp_hdr_t* nfcap_proto_unpack_tcp(const u_char *packet, size_t *offset) {
    tcp_hdr_t *tcp_hdr;
    tcp_hdr = (tcp_hdr_t *) (packet + *offset);

    *offset += tcp_hdr->data_offset * 4;

    return tcp_hdr;
}

int nfcap_proto_tcp_state_machine_send(
    tcp_connection_state_machine_t *state_machine,
    uint8_t flags,
    tcp_connection_state_t peer_state
) {
    int ret = TCP_STATE_MACHINE_SUCCESS;

    // RFC 9293 - Figure 5: TCP Connection State Diagram
    // See Note 3 on the figure
    // https://datatracker.ietf.org/doc/html/rfc9293#section-3.3.2
    if (flags & TCP_RST) {
        state_machine->state = TCP_STATE_TIME_WAIT;
        return ret;
    }
    
    // RFC 9293 - Figure 5: TCP Connection State Diagram
    // https://datatracker.ietf.org/doc/html/rfc9293#section-3.3.2
    switch (state_machine->state) {
        case TCP_STATE_CLOSED:
            if (flags == TCP_SYN) {
                state_machine->state = TCP_STATE_SYN_SENT;
            } else {
                ret = TCP_STATE_MACHINE_ALREADY_ESTABLISHED;
            }
            break;
        case TCP_STATE_LISTEN:
            if (flags == TCP_SYN) {
                state_machine->state = TCP_STATE_SYN_SENT;
            }
            if (peer_state == TCP_STATE_SYN_SENT && flags == TCP_SYN + TCP_ACK) {
                state_machine->state = TCP_STATE_SYN_RECEIVED;    
            }
            break;
        case TCP_STATE_SYN_SENT:
            if (peer_state == TCP_STATE_SYN_SENT && flags == TCP_SYN) {
                state_machine->state = TCP_STATE_SYN_RECEIVED;
            }

            if (peer_state == TCP_STATE_SYN_RECEIVED && flags == TCP_ACK) {
                state_machine->state = TCP_STATE_ESTABLISHED;
            }

            if (flags == TCP_SYN) {
                state_machine->state = TCP_STATE_SYN_SENT;
                ret = TCP_STATE_MACHINE_SYN;
            }
            break;
        case TCP_STATE_SYN_RECEIVED:
            if (flags & TCP_FIN) {
                state_machine->state = TCP_STATE_FIN_WAIT_1;
            }
            break;
        case TCP_STATE_ESTABLISHED:
            if (flags & TCP_FIN) {
                state_machine->state = TCP_STATE_FIN_WAIT_1;
            }

            if (peer_state == TCP_STATE_FIN_WAIT_1 && (flags & TCP_ACK)) {
                state_machine->state = TCP_STATE_CLOSE_WAIT;
            }
            break;
        case TCP_STATE_CLOSE_WAIT:
            if (flags & TCP_FIN) {
                state_machine->state = TCP_STATE_LAST_ACK;
            }
            break;    
        case TCP_STATE_FIN_WAIT_1:
            if (peer_state == TCP_STATE_CLOSE_WAIT && (flags & TCP_ACK)) {
                state_machine->state = TCP_STATE_CLOSING;
            }
            break;
        case TCP_STATE_FIN_WAIT_2:
            if (flags &  TCP_ACK) {
                state_machine->state = TCP_STATE_TIME_WAIT;
            }
        default:
            ret = TCP_STATE_MACHINE_ERROR;
            break;
    }

    return 0;
}

int nfcap_proto_tcp_state_machine_recv(
    tcp_connection_state_machine_t *state_machine,
    uint8_t flags,
    tcp_connection_state_t peer_state
) {
    int ret = TCP_STATE_MACHINE_SUCCESS;
    // RFC 9293 - Figure 5: TCP Connection State Diagram
    // See Note 3 on the figure
    // https://datatracker.ietf.org/doc/html/rfc9293#section-3.3.2
    if (flags & TCP_RST) {
        state_machine->state = TCP_STATE_CLOSED;
        return 0;
    }

    // RFC 9293 - Figure 5: TCP Connection State Diagram
    // https://datatracker.ietf.org/doc/html/rfc9293#section-3.3.2
    switch (state_machine->state) {
        case TCP_STATE_LISTEN:
            if (flags == TCP_SYN) {
                state_machine->state = TCP_STATE_SYN_RECEIVED;
            }
            break;
        case TCP_STATE_SYN_SENT:
            if (flags == TCP_SYN + TCP_ACK) {
                state_machine->state = TCP_STATE_ESTABLISHED;
            }
            break;
            if (flags == TCP_SYN) {
                state_machine->state = TCP_STATE_SYN_RECEIVED;
            }
        case TCP_STATE_SYN_RECEIVED:
            if (flags == TCP_ACK) {
                state_machine->state = TCP_STATE_ESTABLISHED;
            }
            if (flags & TCP_SYN) {
                ret = TCP_STATE_MACHINE_SYN;
            }
            if (flags & TCP_RST) {
                state_machine->state = TCP_STATE_LISTEN;
            }
            break;
        case TCP_STATE_ESTABLISHED:
            if (flags & TCP_FIN) {
                state_machine->state = TCP_STATE_CLOSE_WAIT;
            }

            break;
        case TCP_STATE_LAST_ACK:
            if (flags & TCP_ACK) {
                state_machine->state = TCP_STATE_CLOSED;
            }
            break;
        case TCP_STATE_FIN_WAIT_1:
            if (flags & (TCP_FIN + TCP_ACK)) { // RFC 9293 - 3.3.2 Note 2
                state_machine->state = TCP_STATE_TIME_WAIT;
            } else if (flags & TCP_FIN) {
                state_machine->state = TCP_STATE_CLOSING;
            } else if (flags & TCP_ACK) {
                state_machine->state = TCP_STATE_FIN_WAIT_2;
            }
            break;
        case TCP_STATE_FIN_WAIT_2:
            if (flags & TCP_FIN) {
                state_machine->state = TCP_STATE_TIME_WAIT;
            }
            break;
        case TCP_STATE_CLOSING:
            if (flags & TCP_ACK) {
                state_machine->state = TCP_STATE_TIME_WAIT;
            }
            break;
        default:
            break;
    }

    return ret;
}

int nfcap_proto_tcp_connection_checker_init(tcp_connection_checker_t **checker) {
    *checker = calloc(1, sizeof(tcp_connection_checker_t));
    (*checker)->client_sm.state = TCP_STATE_CLOSED;
    (*checker)->server_sm.state = TCP_STATE_LISTEN;

    return 0;
}

int nfcap_proto_tcp_connection_checker_update(
    tcp_connection_checker_t *checker,
    uint8_t flags,
    uint8_t direction
) {
    int ret = 0;
    if (direction == 0) {
        nfcap_proto_tcp_state_machine_send(&checker->client_sm, flags, checker->server_sm.state);
        ret = nfcap_proto_tcp_state_machine_recv(&checker->server_sm, flags, checker->client_sm.state);
    } else {
        nfcap_proto_tcp_state_machine_send(&checker->server_sm, flags, checker->client_sm.state);
        ret = nfcap_proto_tcp_state_machine_recv(&checker->client_sm, flags, checker->server_sm.state);
    }
    return ret;
}

char* nfcap_proto_tcp_state_to_string(tcp_connection_state_t state) {
    switch (state) {
        case TCP_STATE_CLOSED:
            return "CLOSED";
        case TCP_STATE_LISTEN:
            return "LISTEN";
        case TCP_STATE_SYN_SENT:
            return "SYN_SENT";
        case TCP_STATE_SYN_RECEIVED:
            return "SYN_RECEIVED";
        case TCP_STATE_ESTABLISHED:
            return "ESTABLISHED";
        case TCP_STATE_FIN_WAIT_1:
            return "FIN_WAIT_1";
        case TCP_STATE_FIN_WAIT_2:
            return "FIN_WAIT_2";
        case TCP_STATE_CLOSE_WAIT:
            return "CLOSE_WAIT";
        case TCP_STATE_CLOSING:
            return "CLOSING";
        case TCP_STATE_LAST_ACK:
            return "LAST_ACK";
        case TCP_STATE_TIME_WAIT:
            return "TIME_WAIT";
        default:
            return "UNKNOWN";
    }
}
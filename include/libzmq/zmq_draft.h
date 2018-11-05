/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_DRAFT_H_INCLUDED__
#define __ZMQ_DRAFT_H_INCLUDED__

/******************************************************************************/
/*  These functions are DRAFT and disabled in stable releases, and subject to */
/*  change at ANY time until declared stable.                                 */
/******************************************************************************/

#ifndef ZMQ_BUILD_DRAFT_API

/*  Returns the number of microseconds elapsed since the stopwatch was        */
/*  started, but does not stop or deallocate the stopwatch.                   */
unsigned long zmq_stopwatch_intermediate (void *watch_);

/*  DRAFT Socket types.                                                       */
#define ZMQ_SERVER 12
#define ZMQ_CLIENT 13
#define ZMQ_RADIO 14
#define ZMQ_DISH 15
#define ZMQ_GATHER 16
#define ZMQ_SCATTER 17
#define ZMQ_DGRAM 18

/*  DRAFT Socket options.                                                     */
#define ZMQ_ZAP_ENFORCE_DOMAIN 93
#define ZMQ_LOOPBACK_FASTPATH 94
#define ZMQ_METADATA 95
#define ZMQ_MULTICAST_LOOP 96

/*  DRAFT 0MQ socket events and monitoring                                    */
/*  Unspecified system errors during handshake. Event value is an errno.      */
#define ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL 0x0800
/*  Handshake complete successfully with successful authentication (if        *
 *  enabled). Event value is unused.                                          */
#define ZMQ_EVENT_HANDSHAKE_SUCCEEDED 0x1000
/*  Protocol errors between ZMTP peers or between server and ZAP handler.     *
 *  Event value is one of ZMQ_PROTOCOL_ERROR_*                                */
#define ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL 0x2000
/*  Failed authentication requests. Event value is the numeric ZAP status     *
 *  code, i.e. 300, 400 or 500.                                               */
#define ZMQ_EVENT_HANDSHAKE_FAILED_AUTH 0x4000

#define ZMQ_PROTOCOL_ERROR_ZMTP_UNSPECIFIED 0x10000000
#define ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND 0x10000001
#define ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_SEQUENCE 0x10000002
#define ZMQ_PROTOCOL_ERROR_ZMTP_KEY_EXCHANGE 0x10000003
#define ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_UNSPECIFIED 0x10000011
#define ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_MESSAGE 0x10000012
#define ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_HELLO 0x10000013
#define ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_INITIATE 0x10000014
#define ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_ERROR 0x10000015
#define ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_READY 0x10000016
#define ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_WELCOME 0x10000017
#define ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_METADATA 0x10000018

// the following two may be due to erroneous configuration of a peer
#define ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC 0x11000001
#define ZMQ_PROTOCOL_ERROR_ZMTP_MECHANISM_MISMATCH 0x11000002

#define ZMQ_PROTOCOL_ERROR_ZAP_UNSPECIFIED 0x20000000
#define ZMQ_PROTOCOL_ERROR_ZAP_MALFORMED_REPLY 0x20000001
#define ZMQ_PROTOCOL_ERROR_ZAP_BAD_REQUEST_ID 0x20000002
#define ZMQ_PROTOCOL_ERROR_ZAP_BAD_VERSION 0x20000003
#define ZMQ_PROTOCOL_ERROR_ZAP_INVALID_STATUS_CODE 0x20000004
#define ZMQ_PROTOCOL_ERROR_ZAP_INVALID_METADATA 0x20000005

/*  DRAFT Context options                                                     */
#define ZMQ_THREAD_AFFINITY_CPU_ADD 7
#define ZMQ_THREAD_AFFINITY_CPU_REMOVE 8
#define ZMQ_THREAD_NAME_PREFIX 9
#define ZMQ_ZERO_COPY_RECV 10

/*  DRAFT Socket methods.                                                     */
int zmq_join (void *s_, const char *group_);
int zmq_leave (void *s_, const char *group_);

/*  DRAFT Msg methods.                                                        */
int zmq_msg_set_routing_id (zmq_msg_t *msg_, uint32_t routing_id_);
uint32_t zmq_msg_routing_id (zmq_msg_t *msg_);
int zmq_msg_set_group (zmq_msg_t *msg_, const char *group_);
const char *zmq_msg_group (zmq_msg_t *msg_);

/*  DRAFT Msg property names.                                                 */
#define ZMQ_MSG_PROPERTY_ROUTING_ID "Routing-Id"
#define ZMQ_MSG_PROPERTY_SOCKET_TYPE "Socket-Type"
#define ZMQ_MSG_PROPERTY_USER_ID "User-Id"
#define ZMQ_MSG_PROPERTY_PEER_ADDRESS "Peer-Address"

/******************************************************************************/
/*  Poller polling on sockets,fd and thread-safe sockets                      */
/******************************************************************************/

typedef struct zmq_poller_event_t
{
    void *socket;
#if defined _WIN32
    SOCKET fd;
#else
    int fd;
#endif
    void *user_data;
    short events;
} zmq_poller_event_t;

void *zmq_poller_new (void);
int zmq_poller_destroy (void **poller_p_);
int zmq_poller_add (void *poller_,
                    void *socket_,
                    void *user_data_,
                    short events_);
int zmq_poller_modify (void *poller_, void *socket_, short events_);
int zmq_poller_remove (void *poller_, void *socket_);
int zmq_poller_wait (void *poller_, zmq_poller_event_t *event_, long timeout_);
int zmq_poller_wait_all (void *poller_,
                         zmq_poller_event_t *events_,
                         int n_events_,
                         long timeout_);

#if defined _WIN32
int zmq_poller_add_fd (void *poller_,
                       SOCKET fd_,
                       void *user_data_,
                       short events_);
int zmq_poller_modify_fd (void *poller_, SOCKET fd_, short events_);
int zmq_poller_remove_fd (void *poller_, SOCKET fd_);
#else
int zmq_poller_add_fd (void *poller, int fd, void *user_data, short events);
int zmq_poller_modify_fd (void *poller, int fd, short events);
int zmq_poller_remove_fd (void *poller, int fd);
#endif

int zmq_socket_get_peer_state (void *socket_,
                               const void *routing_id_,
                               size_t routing_id_size_);

/******************************************************************************/
/*  Scheduling timers                                                         */
/******************************************************************************/

typedef void(zmq_timer_fn) (int timer_id_, void *arg_);

void *zmq_timers_new (void);
int zmq_timers_destroy (void **timers_p_);
int zmq_timers_add (void *timers_,
                    size_t interval_,
                    zmq_timer_fn handler_,
                    void *arg_);
int zmq_timers_cancel (void *timers_, int timer_id_);
int zmq_timers_set_interval (void *timers_, int timer_id_, size_t interval_);
int zmq_timers_reset (void *timers_, int timer_id_);
long zmq_timers_timeout (void *timers_);
int zmq_timers_execute (void *timers_);

#endif // ZMQ_BUILD_DRAFT_API

#endif //ifndef __ZMQ_DRAFT_H_INCLUDED__

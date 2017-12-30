/* ***************************************************************************

  tcp.h

  Header file for TCP transport protocol
  This module implements only the functionality needed for a TCP transport

  June 2017 - Created

*************************************************************************** */

#ifndef __TCP_H__
#define __TCP_H__

#include    "ip/options.h"
#include    "ip/error.h"
#include    "ip/types.h"

/* -----------------------------------------
   TCP utility types
----------------------------------------- */
struct tcp_conn_state_t
{
    ip4_addr_t  localIP;                                // local IP address to bind this PCB
    uint16_t    localPort;                              // local port to bind this PCB
    ip4_addr_t  remoteIP;                               // remote IP source
    uint16_t    remotePort;                             // remote port of source IP
    pcb_state_t state;                                  // PCB state
};

/* -----------------------------------------
   TCP protocol functions
----------------------------------------- */
/* initialize open and close TCP connections
 */
void              tcp_init(void);                       // Initialize the TCP protocol
pcbid_t           tcp_new(void);                        // create a TCP connection and return TCP PCB which was created. NULL if the PCB data structure could not be allocated.
ip4_err_t         tcp_notify(pcbid_t,                   // notify a bound connection of changes, such as remote disconnection
                             tcp_notify_callback);
ip4_err_t         tcp_bind(pcbid_t,                     // bind a PCB connection to a local IP address and a port
                           ip4_addr_t,
                           uint16_t);
ip4_err_t         tcp_close(pcbid_t);                   // close a TCP connection and clear its PCB

/* server connection
 */
ip4_err_t         tcp_listen(pcbid_t);                  // server's passive-open to TCP_MAX_ACCEPT incoming client connections
ip4_err_t         tcp_accept(pcbid_t,                   // register an accept callback that will be called when
                             tcp_accept_callback);      // a client connects to the open server PCB
/* client connection
 */
ip4_err_t         tcp_connect(pcbid_t,                  // connect a TCP client to a server's IP address and a port
                              ip4_addr_t,               // NOTE: in this implementation use tcp_bind() first
                              uint16_t);
int               tcp_is_connected(pcbid_t);            // to poll if a tcp_connect() request was successful

/* send and receive functions
 */
int               tcp_send(pcbid_t,                     // send data from a buffer, returns byte count actually sent
                           uint8_t* const,              // application/user source buffer
                           uint16_t,                    // byte count to send
                           uint16_t);                   // flags: 0 or TCP_FLAG_PSH or TCP_FLAG_URG (TCP_FLAG_URG not implemented)
int               tcp_recv(pcbid_t,                     // received data, returns byte counts read into application/user buffer
                           uint8_t* const,              // application/user receive buffer
                           uint16_t);                   // byte count available in receive buffer

/* connection utilities
 */
ip4_addr_t        tcp_remote_addr(pcbid_t);             // get remote address of a connection
uint16_t          tcp_remote_port(pcbid_t);             // get remote port of a connection
int               tcp_util_conn_state(pcbid_t,          // get TCP connection info/state
                                      struct tcp_conn_state_t*);

#endif /* __TCP_H__ */

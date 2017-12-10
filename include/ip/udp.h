/* ***************************************************************************

  udp.h

  Header file for UDP transport protocol
  This module implements only the functionality needed for a UDP transport

  June 2017 - Created

*************************************************************************** */

#ifndef __UDP_H__
#define __UDP_H__

#include    "ip/options.h"
#include    "ip/error.h"
#include    "ip/types.h"

/* -----------------------------------------
   UDP protocol functions
----------------------------------------- */
void              udp_init(void);                   // Initialize the UDP protocol
struct udp_pcb_t* udp_new(void);                    // create a UDP connection and return UDP PCB which was created. NULL if the PCB data structure could not be allocated.
void              udp_close(struct udp_pcb_t*);     // close a UDP connection and clear its PCB

ip4_err_t         udp_bind(struct udp_pcb_t*,       // bind a PCB connection to a local IP address and a port
                           const ip4_addr_t,
                           uint16_t);

ip4_err_t         udp_sendto(struct udp_pcb_t*,     // send datagram data from a buffer to a destination IP address and port
                             uint8_t* const,
                             uint16_t,
                             const ip4_addr_t,
                             uint16_t);
ip4_err_t         udp_recv(struct udp_pcb_t*,       // registers a callback to handle received data
                           udp_recv_callback);

#endif /* __UDP_H__ */

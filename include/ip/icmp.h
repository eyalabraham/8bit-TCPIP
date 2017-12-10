/* ***************************************************************************

  icmp.h

  Header file for ICMP Ping protocol
  This module implements only the functionality needed for a Ping application

  May 2017 - Created

*************************************************************************** */

#ifndef __ICMP_H__
#define __ICMP_H__

#include    "ip/options.h"
#include    "ip/error.h"
#include    "ip/types.h"

/* -----------------------------------------
   ICMP PING protocol functions
----------------------------------------- */
void      icmp_ping_init(void (*ping_input)(struct pbuf_t* const)); // initialize ICMP Ping response processing
ip4_err_t icmp_ping_output(ip4_addr_t, uint16_t, uint16_t,
                           uint8_t* const, uint8_t);                // output an ICMP Ping packet

#endif /* __ICMP_H__ */

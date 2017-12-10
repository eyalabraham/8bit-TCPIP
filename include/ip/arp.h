/* ***************************************************************************

  arp.h

  header file for network ARP protocol

  May 2017 - Created

*************************************************************************** */

#ifndef __ARP_H__
#define __ARP_H__

#include    "ip/options.h"
#include    "ip/error.h"
#include    "ip/types.h"

/* -----------------------------------------
   ARP interface and utility functions
----------------------------------------- */
void            arp_init(void);                             // initialize ARP functionality
hwaddr_t* const arp_query(struct net_interface_t* const,    // search the table for HW address of an IP address
                          ip4_addr_t);
ip4_err_t arp_tbl_entry(struct net_interface_t* const,      // add or update an ARP entry to the table
                        ip4_addr_t,
                        hwaddr_t,
                        arp_flags_t);
struct arp_tbl_t* const arp_show(void);                     // repeated calls to this function will walk the ARP table

void      arp_input(struct pbuf_t* const,                   // link layer packet handler for handling incoming ARP or forwarding
                    struct net_interface_t* const);
ip4_err_t arp_output(struct net_interface_t* const,         // packet output function with address resolution,
                     struct pbuf_t* const);
ip4_err_t arp_gratuitous(struct net_interface_t* const);    // send a gratuitous ARP message

#endif /* __ARP_H__ */

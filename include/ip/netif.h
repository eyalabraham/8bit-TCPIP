/* ***************************************************************************

  netif.h

  header file for the network interface types

  May 2017 - Created

*************************************************************************** */

#ifndef __NETIF_H__
#define __NETIF_H__

#include    "ip/options.h"
#include    "ip/error.h"
#include    "ip/types.h"

/* -----------------------------------------
   network interface functions
----------------------------------------- */
ip4_err_t   interface_init(struct net_interface_t* const,           // interface initialization ( also calls enc28j60Init() )
                           struct netif_call_backs_t* const);
void        interface_input(struct net_interface_t* const);         // poll for input packets and forward up the stack for processing
void        interface_set_addr(struct net_interface_t* const,       // setup interface's IP, Gateway and Subnet Mask
                               ip4_addr_t, ip4_addr_t, ip4_addr_t);
void        interface_set_mac(struct net_interface_t* const,        // setup interface's MAC address
                              hwaddr_t);
void        interface_set_name(struct net_interface_t* const,       // setup interface's name string
                               char*, int);
int         interface_link_state(struct net_interface_t* const);    // link state probe

#endif /* __NETIF_H__ */

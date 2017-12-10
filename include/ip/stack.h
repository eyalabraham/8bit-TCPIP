/* ***************************************************************************

  ip4stack.h

  header file for the Ipv4 stack

  May 2017 - Created

*************************************************************************** */

#ifndef __IP4STACK_H__
#define __IP4STACK_H__

#include    <sys/types.h>

#include    "ip/options.h"
#include    "ip/error.h"
#include    "ip/types.h"

/* -----------------------------------------
   IPv4 interface and utility functions
----------------------------------------- */
#define     stack_hton(x)       stack_ntoh(((uint16_t)x))
#define     stack_htonl(x)      stack_ntohl(((uint32_t)x))
#define     stack_checksum(p,l) stack_checksumEx(p,l,0UL)

void                            stack_init(void);                                       // initialize the IP stack
struct net_interface_t* const   stack_get_ethif(uint8_t);                               // get pointer to an interface on the stack
ip4_err_t                       stack_set_route(ip4_addr_t, ip4_addr_t, uint8_t);       // add a route to the route table
struct route_tbl_t* const       stack_get_route(uint8_t);                               // get pointer to route table entry
ip4_err_t                       stack_clear_route(uint8_t);                             // clear route table entry
uint32_t                        stack_time(void);                                       // return stack time in mSec
void                            stack_timers(void);                                     // handle stack timers and timeouts for all network interfaces
ip4_err_t                       stack_set_timer(uint32_t, timer_callback_fn);           // register a timer call back and time out
void                            stack_set_protocol_handler(ip4_protocol_t,              // setup input handler per protocol
                                                           void (*)(struct pbuf_t* const));

struct pbuf_t* const            pbuf_allocate(void);                                    // allocate a transmit or receive buffer
void                            pbuf_free(struct pbuf_t* const);                        // free a buffer allocation

uint16_t                        stack_ntoh(uint16_t);                                   // big-endian to little-endian 16bit bytes swap
uint32_t                        stack_ntohl(uint32_t);                                  // big-endian to little-endian 32bit bytes swap
uint16_t                        stack_checksumEx(const void*, int, uint32_t);           // checksum calculation
char*                           stack_ip4addr_ntoa(ip4_addr_t, char* const, uint8_t);   // convert network address to string representation

void                            inputStub(struct pbuf_t* const,                         // input stub function
                                          struct net_interface_t* const);

#endif /* __IP4STACK_H__ */

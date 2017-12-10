/* ***************************************************************************

  netif.c

   this is the network interface module.
   it implements a common interface layer between the HW driver and the other
   layers of the stack

   Eyal Abraham, May 2017

*************************************************************************** */

#include    <malloc.h>
#include    <string.h>

#include    "ip/netif.h"
#include    "ip/stack.h"
#include    "ip/ipv4.h"
#include    "ip/arp.h"
#include    "ip/enc28j60.h"
#include    "ip/slip.h"

/* -----------------------------------------
 * interface_init()
 *
 * Should be called at the beginning of the program to set up the
 * network interface. This implementation calls the function
 * enc28j60Init() to do the actual setup of the ENC28J60 hardware.
 * This function can be extended to cycle through available interfaces
 * and for each, call its own <device>Init() function.
 *
 * param:  'netif' the network stack structure to which this interface connects
 * return: ERR_OK or any other ip4_err_t on error
 *
 * TODO variables hard coded in this function, like MAC address
 *    or function pointers should be passed as variables. this will make the
 *    function general for use with any link interface driver!
 *
 */
ip4_err_t interface_init(struct net_interface_t* const netif)
{
    ip4_err_t     result = ERR_NETIF;                   // signal an interface error

    memset(netif, 0, sizeof(struct net_interface_t));   // clear structure

    netif->hwaddr[0] = MAC0;                            // initialize mac address
    netif->hwaddr[1] = MAC1;
    netif->hwaddr[2] = MAC2;
    netif->hwaddr[3] = MAC3;
    netif->hwaddr[4] = MAC4;
    netif->hwaddr[5] = MAC5;

    netif->flags = IF_FLAG_INIT;                        // device capabilities and identification
    strncpy(netif->name, ETHIF_NAME, ETHIF_NAME_LENGTH);

    arp_tbl_entry(netif,                                // add loop-back IP address
                  IP4_ADDR(127,0,0,1),
                  netif->hwaddr,
                  ARP_FLAG_STATIC);

    /* initialize interface function calls
     *
     */
    netif->output = arp_output;                         // to be called when address resolution is required
    netif->forward_input = arp_input;                   // forward frame through ARP module for processing or forwarding to network layer

    netif->linkinput = link_input;                      // to be called to get waiting packet from the link interface
    netif->linkoutput = link_output;                    // to be called when as-is data needs to be sent, without address resolution
    netif->driver_init = (void *(*)(void))enc28j60Init; // driver initialization function
    netif->linkstate = link_state;                      // link state from driver

    /* initialize the HW interface
     *
     */
    if ( (netif->state = netif->driver_init()) != NULL )
    {
        netif->flags |= (NETIF_FLAG_LINK_UP | NETIF_FLAG_UP);   // if ENC28J60 initializes properly then set state to link up
        result = ERR_OK;
    }
    return result;
}

/* -----------------------------------------
 * interface_slip_init()
 *
 * Should be called at the beginning of the program to set up a
 * SLIP network interface.
 *
 * param:  'netif' the network stack structure to which this interface connects
 * return: ERR_OK or any other ip4_err_t on error
 *
 * TODO variables hard coded in this function, and it is specialized
 *      only for SLIP. It can only be called once, for one interface.
 *      there are no checks preventing multiple calls!
 *
 */
ip4_err_t interface_slip_init(struct net_interface_t* const netif)
{
    ip4_err_t     result = ERR_NETIF;                   // signal an interface error

    memset(netif, 0, sizeof(struct net_interface_t));   // clear structure

    netif->flags = IF_FLAG_INIT;                        // device capabilities and identification
    strncpy(netif->name, SLIP_NAME, ETHIF_NAME_LENGTH);

    /* initialize interface function calls
     *
     */
    netif->output = slip_output;                        // no address resolution is needed in SLIP, packet is sent directly
    netif->forward_input = ip4_input;                   // for SLIP forward packet directly to IPv4 module for processing

    netif->linkinput = slip_input;                      // to be called to get waiting packet from the link interface
    netif->linkoutput = NULL;                           // not needed with SLIP, IPv4 calls slip_output() through netif->output member
    netif->driver_init = (void *(*)(void))slip_init;    // driver initialization function
    netif->linkstate = slip_link_state;                 // link state from driver

    /* initialize the serial HW interface
     *
     */
    if ( (netif->state = netif->driver_init()) != NULL )
    {
        netif->flags |= (NETIF_FLAG_LINK_UP | NETIF_FLAG_UP);   // if ENC28J60 initializes properly then set state to link up
        result = ERR_OK;
    }
    return result;
}

/* -----------------------------------------
 * interface_input()
 *
 * This function should be called periodically from the main program loop.
 * It uses the function low_level_input() that polls the interface and handles
 * the actual reception of bytes from the network interface.
 * Then the type of the received packet is determined and
 * the appropriate input function is called.
 *
 * param:  netif the network interface structure for this ethernet interface
 * return: none
 *
 */
void interface_input(struct net_interface_t* const netif)
{
    struct pbuf_t*  p;

    // move received packet into a new pbuf
    if ( netif->linkinput )
        p = netif->linkinput(netif);                    // this function does a pbuf_allocate()

    // if no packet could be read, silently ignore this
    if (p != NULL)
    {
        // forward packets to next layer for processing
        if ( netif->forward_input )
            netif->forward_input(p, netif);             // forward the IP packet up the stack if a handler exists
        pbuf_free(p);                                   // free the pbuf after packet processing is complete
    }
}

/* -----------------------------------------
 * interface_set_addr()
 *
 * This function setups up an interface's IP, Gateway and Subnet Mask.
 *
 * param:  netif the network interface and three IP addresses
 * return: none
 *
 */
void interface_set_addr(struct net_interface_t* const netif,
                               ip4_addr_t ip, ip4_addr_t netmask, ip4_addr_t gw)
{
    netif->ip4addr = ip;
    netif->subnet = netmask;
    netif->gateway = gw;
    netif->network = gw & netmask;
}

/* -----------------------------------------
 * interface_link_state()
 *
 * This function This function returns the link status
 *
 * param:  netif the network interface to be polled
 * return: '1' or '0' for link 'up' or 'down'
 *
 */
int interface_link_state(struct net_interface_t* const netif)
{
    int     state = 0;

    if ( netif->linkstate )
        state = netif->linkstate();

    if ( state == 1 )
        netif->flags |= NETIF_FLAG_LINK_UP;
    else
        netif->flags &= ~NETIF_FLAG_LINK_UP;

    return state;
}

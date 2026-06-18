/* ***************************************************************************

  netif.c

   this is the network interface module.
   it implements a common interface layer between the HW driver and the other
   layers of the stack

   Eyal Abraham, May 2017

*************************************************************************** */

#include    <string.h>

#include    "ip/netif.h"
#include    "ip/stack.h"
#include    "ip/ipv4.h"

/* -----------------------------------------
 * interface_init()
 *
 * Should be called at the beginning of the program to set up the
 * network interface. The implementation calls the 'driver_init' function
 * to do the actual setup of the link hardware (ENC28J60, SLIP, PLIP etc.)
 *
 * param:  'netif' the network stack structure to which this interface connects
 * return: ERR_OK or any other ip4_err_t on error
 *
 */
ip4_err_t interface_init(struct net_interface_t* const netif,
                         struct netif_call_backs_t* const call_backs)
{
    ip4_err_t     result = ERR_NETIF;                   // signal an interface error

    memset(netif, 0, sizeof(struct net_interface_t));   // clear structure

    netif->flags = IF_FLAG_INIT;                        // device capabilities and identification

    /* initialize interface function calls
     *
     */
    netif->output = call_backs->output;                 // to be called when address resolution is required
    netif->forward_input = call_backs->forward_input;   // forward frame through ARP module for processing or forwarding to network layer

    netif->linkinput = call_backs->linkinput;           // to be called to get waiting packet from the link interface
    netif->linkoutput = call_backs->linkoutput;         // to be called when as-is data needs to be sent, without address resolution
    netif->driver_init = call_backs->driver_init;       // driver initialization function
    netif->linkstate = call_backs->linkstate;           // link state from driver

    /* initialize the HW interface
     *
     */
    if ( (netif->state = netif->driver_init()) != NULL )
    {
        netif->flags |= (NETIF_FLAG_LINK_UP | NETIF_FLAG_UP);
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
 * This function sets up an interface's IP, Gateway and Subnet Mask.
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
 * interface_set_mac()
 *
 *  This function sets up an interface's MAC hardware address
 *
 * param:  netif the network interface and three IP addresses,
 *         and MAC address structure
 * return: none
 *
 */
void interface_set_mac(struct net_interface_t* const netif,
                       hwaddr_t hw_address)
{
    netif->hwaddr[0] = hw_address[0];
    netif->hwaddr[1] = hw_address[1];
    netif->hwaddr[2] = hw_address[2];
    netif->hwaddr[3] = hw_address[3];
    netif->hwaddr[4] = hw_address[4];
    netif->hwaddr[5] = hw_address[5];
}

/* -----------------------------------------
 * interface_set_name()
 *
 * This function sets up an interface's IP name string.
 *
 * param:  netif the network interface and three IP addresses,
 *         name string and string length.
 * return: none
 *
 */
void interface_set_name(struct net_interface_t* const netif,
                        char* name, int name_len)
{
    strncpy(netif->name, name, name_len);
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

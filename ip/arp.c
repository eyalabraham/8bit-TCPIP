/* ***************************************************************************

  arp.c

  network ARP protocol code module

  May 2017 - Created

*************************************************************************** */

#include    <malloc.h>
#include    <string.h>
#include    <assert.h>

#include    "ip/arp.h"
#include    "ip/ipv4.h"
#include    "ip/stack.h"

/* -----------------------------------------
   static functions
----------------------------------------- */
static ip4_err_t arp_send(struct net_interface_t* const, hwaddr_t*, hwaddr_t*,
                          uint16_t, hwaddr_t*, ip4_addr_t, hwaddr_t*, ip4_addr_t);
static ip4_err_t arp_queue(ip4_addr_t, struct net_interface_t* const, struct pbuf_t* const);
static void      arp_unqueue(void);
static void      arp_queue_clr(uint32_t);
static void      arp_cache_clr(uint32_t);

/* -----------------------------------------
   globals
----------------------------------------- */
hwaddr_t    zero      = {0,0,0,0,0,0};
hwaddr_t    broadcast = {0xff,0xff,0xff,0xff,0xff,0xff};
struct arp_queue_t  arpQ[ARP_QUEUE_LENGTH];
int         arpQueuedCount = -1;                            // initialized to '-1' to trigger initialization of the table

/* -----------------------------------------
 * arp_query()
 *
 * initialize ARP functionality
 *
 * param:  none
 * return: none
 *
 */
void arp_init(void)
{
    int     i;

    if ( arpQueuedCount < 0 )                           // one time initialization guard of the queue
    {
        for (i = 0; i < ARP_QUEUE_LENGTH; i++)
        {
            arpQ[i].ipAddr = 0;
            arpQ[i].p = NULL;
            arpQ[i].netif = NULL;
            arpQ[i].queued = 0;
        }
        arpQueuedCount = 0;                             // do this only once!
    }

    stack_set_timer((ARP_QUEUE_EXPR/3), arp_queue_clr); // register ARP clean-up callback
    stack_set_timer((ARP_CACHE_EXPR/10), arp_cache_clr);
}

/* -----------------------------------------
 * arp_query()
 *
 * This function searches the ARP table for and IP address
 * that matches ipArrd and return a pointer to the HW address.
 * The function uses the IP address as the key for the serach
 *
 * param:  netif the network interface and IP address to search
 * return: pointer to HW address if found, or NULL if not
 *
 */
hwaddr_t* const arp_query(struct net_interface_t* const netif,
                          ip4_addr_t ipAddr)
{
    int         i;
    hwaddr_t   *result = NULL;

    for (i = 0; i < ARP_TABLE_LENGTH; i++)
    {
        if ( netif->arpTable[i].ipAddress == ipAddr )   // check if IP address exists
        {
            result = netif->arpTable[i].hwAddress;      // return pointer to HW address
            break;
        }
    }

    return result;
}

/* -----------------------------------------
 * arp_tbl_entry()
 *
 * This function adds or updates an ARP entry to the table.
 * the function uses the ipAddress as the key and the
 * hwAddr and flags as the values.
 *
 * param:  netif the network interface and IP and HW address and flags
 * return: ERR_OK if entry was added, ip4_err_t if not
 *
 */
ip4_err_t arp_tbl_entry(struct net_interface_t* const netif,
                        ip4_addr_t ipAddr,
                        hwaddr_t hwAddr,
                        arp_flags_t flags)
{
    int         i;
    int         freeSlot = -1;
    ip4_err_t   result = ERR_ARP_FULL;
    uint32_t    now, cachedTime, oldestCacheTime = 0;
    int         oldestSlot;

    now = stack_time();
    for (i = 0; i < ARP_TABLE_LENGTH; i++)                                          // first scan table to
    {
        cachedTime = now - netif->arpTable[i].cached;                               // calculate how long was the entry cached
        if ( cachedTime > oldestCacheTime &&                                        // identify oldest slot
             netif->arpTable[i].flags == ARP_FLAG_DYNA )
        {
            oldestSlot = i;                                                         // in case we need it later
            oldestCacheTime = cachedTime;
        }

        if ( netif->arpTable[i].ipAddress == ipAddr )                               // check if IP address exists
        {
            copy_hwaddr(netif->arpTable[i].hwAddress, hwAddr);                      // update the ARP information
            netif->arpTable[i].flags &= ~(ARP_FLAG_STATIC | ARP_FLAG_DYNA);
            netif->arpTable[i].flags |= flags;
            netif->arpTable[i].cached = now;                                        // reset access time to now
            result = ERR_OK;
            freeSlot = -1;                                                          // entry updated, no need to add it
            break;                                                                  // entry update, so done and exit scan loop here
        }

        if ( (netif->arpTable[i].flags & (ARP_FLAG_STATIC | ARP_FLAG_DYNA)) == 0 )  // look for a free slot as we traverse the table
            freeSlot = i;                                                           // and mark for later, just in case we need to 'add'
    }

    if ( freeSlot != -1 )                                                           // entry needs to be added
    {
        netif->arpTable[freeSlot].ipAddress = ipAddr;                               // add the ARP information
        copy_hwaddr(netif->arpTable[freeSlot].hwAddress, hwAddr);
        netif->arpTable[freeSlot].flags |= flags;
        netif->arpTable[freeSlot].cached = stack_time();
        result = ERR_OK;
    }

    if ( result == ERR_ARP_FULL )                                                   // if no free slots found
    {
        netif->arpTable[oldestSlot].ipAddress = ipAddr;                             // overwrite the oldest slot
        copy_hwaddr(netif->arpTable[oldestSlot].hwAddress, hwAddr);
        netif->arpTable[oldestSlot].flags |= flags;
        netif->arpTable[oldestSlot].cached = stack_time();
        result = ERR_OK;
    }

    return result;
}

/* -----------------------------------------
 * arp_show()
 *
 * Repeated calls to this function will walk the ARP table
 *
 * param:  none
 * return: pointer to ARP table record
 *
 */
struct arp_tbl_t* const arp_show(void)
{
    return NULL;
}

/* -----------------------------------------
 * arp_input()
 *
 * This function is the link layer packet handler for handling incoming ARP.
 * packet are forwarded here from the input interface and will be parsed for ARP
 * processing and reply or forwarded to next layer
 *
 * packets arriving here from the link interface should be already
 * filtered to have either broadcast address or our MAC address
 * as their destination.
 * if not, additional filtering/handling should be done here
 * the function only does a minimal check of the fields in the ARP packet
 * such as HTYPE = 1 and PTYPE = 0x0800
 *
 * this function does the following:
 * 1. examine type field
 * 2. process ARP request
 * 3. forward IPv4 type to network layer
 * 4. discard all the rest
 *
 * param:  packet buffer pointer and netif the network interface
 *         structure for this ethernet interface
 * return: none
 *
 */
void arp_input(struct pbuf_t* const p, struct net_interface_t* const netif)
{
    struct ethernet_frame_t *frame;
    struct arp_t            *arp;

    frame = (struct ethernet_frame_t*) p->pbuf;             // recast frame structure
    arp   = (struct arp_t*) &frame->payloadStart;           // pointer to ARP data payload

    switch ( stack_ntoh(frame->type) )                      // determine frame type
    {
        case TYPE_ARP:                                      // handle ARP frames
            if ( stack_ntoh(arp->htype) != ARP_ETH_TYPE || stack_ntoh(arp->ptype) != TYPE_IPV4 )
                break;                                      // drop the packet if not matching on network and protocol type
            switch ( stack_ntoh(arp->oper) )                // action is based on the operation indicator
            {
                case ARP_OP_REQUEST:
                    if ( arp->tpa == netif->ip4addr )       // is someone looking for us?
                    {
                        arp_send(netif, frame->src, netif->hwaddr,
                                 ARP_OP_REPLY, netif->hwaddr, netif->ip4addr, arp->sha, arp->spa);
                    }
                    break;

                case ARP_OP_REPLY:                          // use replies to update the table
                    arp_tbl_entry(netif, arp->spa, arp->sha, ARP_FLAG_DYNA);
                    arp_unqueue();                          // check if there are any queued packets waiting for address resolution
                    break;

                default:;                                   // drop the packet
            }
            break;  /* end of handling TYPE_ARP */

        case TYPE_IPV4:                                     // forward regular IPv4 frames
            ip4_input(p, netif);                            // all inputs go here from any network interface
            break;  /* end of handling TYPE_IPV4 */

        default:;                                           // drop everything else TODO handle unidentified frame types
    } /* end of frame type switch */
}

/* -----------------------------------------
 * arp_output()
 *
 * This function is the link layer packet handler for handling outgoing packets
 * that require address resolution ARP.
 * packets are forwarded here, IP addresses are resolved to network MAC addresses
 * and sent
 *
 * param:  packet buffer pointer and netif the network interface
 *         structure for this ethernet interface
 * return: ERR_OK if no errors or error level from ip4_err_t
 *
 */
ip4_err_t arp_output(struct net_interface_t* const netif, struct pbuf_t* const p)
{
    struct ethernet_frame_t *frame;
    struct ip_header_t      *ipHeader;
    hwaddr_t                *hwaddr;
    ip4_addr_t               destIp;
    ip4_err_t                result, queue_result;

    frame = (struct ethernet_frame_t*) p->pbuf;                     // establish pointer to ethernet frame
    ipHeader = (struct ip_header_t*) &(frame->payloadStart);        // establish pointer to IP header

    /* extract destination IP and check if it is in this
     * interface's subnet. if it is not, then send the packet
     * to the gateway (ARP for the gateway's address if needed)
     * otherwise resolve the target address and send as usual
     */
    if ( (ipHeader->destIp & netif->subnet) == netif->network )     // check network association
    {
        destIp = ipHeader->destIp;                                  // use destination IP as is
    }
    else
    {
        destIp = netif->gateway;                                    // this packet needs to go to the router/gateway
    }

    hwaddr = arp_query(netif, destIp);                              // resolve HW address
    if ( hwaddr )                                                   // was an entry found in the table?
    {                                                               // yes:
        copy_hwaddr(frame->src, netif->hwaddr);                     // copy source HW address as our address
        copy_hwaddr(frame->dest, hwaddr);                           // copy destination HW address
        frame->type = stack_ntoh(TYPE_IPV4);                        // IPv4 frame type
        if ( (netif->flags & (NETIF_FLAG_UP + NETIF_FLAG_LINK_UP)) && netif->linkoutput )
            result = netif->linkoutput(netif, p);                   // send the frame *** p->len should already be set ***
        else
            result = ERR_NETIF;
    }
    else
    {                                                               // no:
        queue_result = arp_queue(destIp, netif, p);                 // queue the packet to be sent when ARP response comes back
        result = arp_send(netif, broadcast, netif->hwaddr,          // send an ARP request to resolve the IP address
                 ARP_OP_REQUEST, netif->hwaddr, netif->ip4addr, broadcast, destIp);
        if ( result == ERR_OK &&
             queue_result == ERR_OK )
            result = ERR_ARP_QUEUE;                                 // address resolution was required, ARP request sent and packet was queued
        else
            result = ERR_ARP_NONE;                                  // ARP request not failed, packed was dropped and *not* queued
    }

    return result;
}

/* -----------------------------------------
 * arp_gratuitous()
 *
 *  This function sends a gratuitous ARP message
 *
 * param:  structure for this ethernet interface
 * return: ERR_OK if no errors or error level from ip4_err_t
 *
 */
ip4_err_t arp_gratuitous(struct net_interface_t* const netif)
{
    return arp_send(netif, broadcast, netif->hwaddr,
                    ARP_OP_REQUEST, netif->hwaddr, netif->ip4addr, zero, netif->ip4addr);
}

/* -----------------------------------------
 * arp_send()
 *
 *  This function sends an ARP packet after assembling it.
 *  It uses link_output()
 *
 * param:  packet buffer pointer and netif the network interface
 *         structure for this ethernet interface
 * return: ERR_OK if no errors or error level from ip4_err_t
 *
 */
static ip4_err_t arp_send(struct net_interface_t* const netif, hwaddr_t *dest, hwaddr_t *src,
                          uint16_t oper, hwaddr_t *sha, ip4_addr_t spa, hwaddr_t *tha, ip4_addr_t tpa)
{
    struct pbuf_t           *p;
    struct ethernet_frame_t *frame;
    struct arp_t            *arp;
    ip4_err_t                result = ERR_OK;

    p = pbuf_allocate();                                        // allocation a transmit buffer
    if ( p )
    {
        frame = (struct ethernet_frame_t*) p->pbuf;             // establish pointer to etherner frame
        copy_hwaddr(frame->dest, dest);                         // build request header
        copy_hwaddr(frame->src, src);
        frame->type = stack_ntoh(TYPE_ARP);

        arp = (struct arp_t*) &(frame->payloadStart);           // establish pointer to ARP request packet
        arp->htype = stack_ntoh(ARP_ETH_TYPE);                  // build ARP packet
        arp->ptype = stack_ntoh(TYPE_IPV4);
        arp->hlen = ARP_HLEN;
        arp->plen = ARP_PLEN;
        arp->oper = stack_ntoh(oper);
        copy_hwaddr(arp->sha, sha);
        arp->spa = spa;
        copy_hwaddr(arp->tha, tha);
        arp->tpa = tpa;

        p->len = FRAME_HDR_LEN + ARP_LEN;
        if ( (netif->flags & (NETIF_FLAG_UP + NETIF_FLAG_LINK_UP)) && netif->linkoutput )
            result = netif->linkoutput(netif, p);               // send the frame
        else
            result = ERR_NETIF;
        pbuf_free(p);                                           // free the pbuf
    }
    else
    {
        result = ERR_MEM;                                       // buffer allocation failed
    }

    return result;
}

/* -----------------------------------------
 * arp_queue()
 *
 *  This function queues the packet buffer passed to it
 *  and lists the IP address that is waiting for resolution,
 *  the buffer pointer, and the queuing expiration time in the
 *  packet queuing table.
 *
 * param:  packet buffer pointer and netif the network interface
 *         structure for this ethernet interface
 * return: ERR_OK if no errors or error level from ip4_err_t
 *
 */
static ip4_err_t arp_queue(ip4_addr_t addr, struct net_interface_t* const netif, struct pbuf_t* const p)
{
    struct pbuf_t  *q;
    int             i;
    ip4_err_t       result;

    for (i = 0; i < ARP_QUEUE_LENGTH; i++)      // first scan packet queue for an available slot
    {                                           // do this before allocating a pbuf
        if ( arpQ[i].ipAddr == 0 )              // just in case a slot is not available
            break;
    }

    if ( i == ARP_QUEUE_LENGTH )                // no queuing slot found
        return ERR_MEM;                         // so exit here

    q = pbuf_allocate();                        // try to allocate a packet buffer
    if ( q != NULL )
    {
        memcpy(q->pbuf, p->pbuf, p->len);       // copy our transmission packet to the new queued buffer
        q->len = p->len;
        arpQ[i].ipAddr = addr;                  // record the queued IP address
        arpQ[i].p = q;                          // the packet waiting to be transmitted
        arpQ[i].netif = netif;                  // the output interface
        arpQ[i].queued = stack_time();          // the time the packet was queued
        arpQueuedCount++;
        result = ERR_OK;
    }
    else
    {
        result = ERR_MEM;
    }

    return result;
}

/* -----------------------------------------
 * arp_unqueue()
 *
 *  This function checks the ARP queue for packets waiting for
 *  address resolution.
 *  the function will scan the queue if required and attempt to send
 *  the waiting packets. if their destination IP is not resolved yet,
 *  the packets will remain queued until their queuing time expires
 *  at which point they will be discarded; recovery is left to the upper
 *  layer protocol
 *
 *
 * param:  none
 * return: none
 *
 */
static void arp_unqueue(void)
{
    struct ethernet_frame_t *frame;
    hwaddr_t                *hwaddr;
    ip4_err_t                result;
    uint32_t                 queueTime;
    int                      i;

    if ( arpQueuedCount <= 0 )                                              // exit if queue is empty or not initialized
        return;

    for (i = 0; i < ARP_QUEUE_LENGTH; i++)
    {
        if ( arpQ[i].ipAddr == 0 )                                          // skip empty queue slots
            continue;

        hwaddr = arp_query(arpQ[i].netif, arpQ[i].ipAddr);                  // try to resolve HW address
        if ( hwaddr )                                                       // was an entry found in the table?
        {                                                                   // yes:
            frame = (struct ethernet_frame_t*) arpQ[i].p->pbuf;             // establish pointer to ethernet frame
            copy_hwaddr(frame->src, arpQ[i].netif->hwaddr);                 // copy source HW address as our address
            copy_hwaddr(frame->dest, hwaddr);                               // copy destination HW address
            frame->type = stack_ntoh(TYPE_IPV4);                            // IPv4 frame type
            if ( (arpQ[i].netif->flags & (NETIF_FLAG_UP + NETIF_FLAG_LINK_UP)) && arpQ[i].netif->linkoutput )
                arpQ[i].netif->linkoutput(arpQ[i].netif, arpQ[i].p);        // send the frame

            pbuf_free(arpQ[i].p);                                           // we're done, free the pbuf
            arpQ[i].ipAddr = 0;                                             // drop the packet even if there are errors sending it
            arpQ[i].p = NULL;                                               // clear the queue slot
            arpQ[i].netif = NULL;
            arpQ[i].queued = 0;
            arpQueuedCount--;
        }
    }
}

/* -----------------------------------------
 * arp_queue_clr()
 *
 *  periodic timer callback function that will clear
 *  expired packets from the packet queue. typically
 *  packets that were queued for an ARP query, but response was not
 *  received.
 *
 *
 * param:  system clock tick when callback was invoked
 * return: none
 *
 */
static void arp_queue_clr(uint32_t now)
{
    int       i;

    if ( arpQueuedCount <= 0 )                              // exit if queue is empty or not initialized
        return;

    for (i = 0; i < ARP_QUEUE_LENGTH; i++)
    {
        if ( arpQ[i].ipAddr == 0 )                          // skip empty queue slots
            continue;

        if ( (now - arpQ[i].queued) > ARP_QUEUE_EXPR )      // check queue expiration time and remove expired packets
        {
            pbuf_free(arpQ[i].p);                           // free the pbuf
            arpQ[i].ipAddr = 0;                             // clear the queue slot
            arpQ[i].p = NULL;
            arpQ[i].netif = NULL;
            arpQ[i].queued = 0;
            arpQueuedCount--;
        }
    }
}

/* -----------------------------------------
 * arp_cache_clr()
 *
 *  periodic timer callback function that will clear
 *  expired ARP cache table entries.
 *
 *
 * param:  system clock tick when callback was invoked
 * return: none
 *
 */
static void arp_cache_clr(uint32_t now)
{
    uint8_t                 ifNum = 0;
    int                     i;
    struct net_interface_t *netif;

    for (ifNum = 0; ifNum < INTERFACE_COUNT; ifNum++)                       // iterate through all interfaces
    {
        netif = stack_get_ethif(ifNum);                                     // get interface
        for (i = 0; i < ARP_TABLE_LENGTH; i++)                              // and through all cache entries
        {
            if ( netif->arpTable[i].flags == ARP_FLAG_DYNA &&               // if a dynamic entry
                 (now - netif->arpTable[i].cached) >= ARP_CACHE_EXPR )      // has expired
            {
                memset(&(netif->arpTable[i]), 0, sizeof(struct arp_tbl_t)); // clear it
            }
        }
    }
}

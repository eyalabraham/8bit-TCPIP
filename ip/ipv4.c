/* ***************************************************************************

  ipv4.c

  IPv4 Network layer services and utilities
  This module include the ICMP implementation for the stack

  May 2017 - Created

*************************************************************************** */

#include    <malloc.h>
#include    <string.h>
#include    <assert.h>

#include    "ip/ipv4.h"
#include    "ip/arp.h"
#include    "ip/stack.h"

/* -----------------------------------------
   module globals
----------------------------------------- */
extern struct ip4stack_t   stack;                                  // IP stack data structure

/* -----------------------------------------
   static functions
----------------------------------------- */
static void ip4_icmp_handler(struct pbuf_t* const, struct net_interface_t* const);

/*------------------------------------------------
 * ip4_input()
 *
 *  IPv4 input packet handler
 *  The handler examines the IP packet, validates IP header and
 *  forwards to TCP, UDP transport handling or processes an ICMP function
 *
 * param:  pointer to the packet's pbuf and the source network interfaces
 * return: none
 *
 */
void ip4_input(struct pbuf_t* const p, struct net_interface_t* const netif)
{
    struct ip_header_t      *ip;
    uint16_t                 chksum, frag;
    int                      ipHeaderLen;

    ip = (struct ip_header_t*) &(((struct ethernet_frame_t*)(p->pbuf))->payloadStart); // pointer to IP packet header

    /*
     * 1. validate header checksum, drop packet if bad
     * 1a. validate destination IP against our IP, drop packet if no match
     * 2. switch on 'protocol' field and handle TCP, UDP or ICMP inputs
     * 3. call protocol handlers with pbuf
     * 4. TODO handling of fragmented packets here?
     * 5. TODO If the header length 'ipHeaderLen' is greater than 5 (i.e., it is from 6 to 15)
     *       it means that the options field is present and must be considered
     *
     */

    ipHeaderLen = (ip->verHeaderLength & 0x0f) * 4;         // calculate header length
    chksum = stack_checksum(ip, ipHeaderLen);               // calculate header checksum
    if ( chksum != 0xffff )                                 // drop packet if checksum is wrong
    {
        return;                                             // TODO report/record checksum error?
    }

    if ( ip->destIp != netif->ip4addr )                     // compare destination IP to our network interface IP
    {
        return;                                             // drop the packet if there is no match
    }

    frag = stack_ntoh(ip->defrag);
    if ( (frag & IP_FLAG_MF) ||                             // TODO drop packets that are fragmented, no reassemble support
         (frag & 0x1fff) > 0 )
    {
        return;
    }

    switch ( ip->protocol )                                 // get IP packet protocol
    {
        case IP4_ICMP:                                      // handle ICMP requests
            ip4_icmp_handler(p, netif);
            break;

        case IP4_UDP:                                       // handle UDP requests
            if ( stack.udp_input_handler )
                stack.udp_input_handler(p);
            break;

        case IP4_TCP:                                       // handle TCP requests
            if ( stack.tcp_input_handler )
                stack.tcp_input_handler(p);
            break;

        default:;                                           // drop everything else TODO handle unidentified frame type
    }
}

/*------------------------------------------------
 * ip4_output()
 *
 *  The function outputs an IPv4 packet, formed in a pbuf
 *  The packet starting with the protocol header header should be formed in a regular pbuf
 *  leaving room at the top of the pbuf for a IPv4 header and a frame header, and then passed
 *  to this function for output.
 *  ip4_output() will build the IPv4 header, then search through the routing table to pick
 *  the appropriate interface. In most cases output will be done through arp_output(), but
 *  with a slip interface this packet will go directly to the output function of SLIP.
 *  The output call uses netif->output that defines the appropriate output function.
 *
 * param:  destination IP, protocol type to be sent, and a pointer to output pbuf
 * return: ERR_OK if send was successful, ip4_err_t on error
 *
 */
ip4_err_t ip4_output(ip4_addr_t dest, ip4_protocol_t protocol, struct pbuf_t* const p)
{
    ip4_err_t               result = ERR_OK;
    struct net_interface_t *netif;
    struct ip_header_t     *ipHeader;
    struct route_tbl_t     *route;
    uint8_t                 i;

    if ( p->len > (FRAME_HDR_LEN + MTU + PACKET_CRC_LEN) )                      // TODO drop packets that are larger than MTU, no fragmentation support
        return ERR_MTU_EXD;

    ipHeader = (struct ip_header_t*) &(p->pbuf[FRAME_HDR_LEN]);

    /* build the IP header and populate it with the common fields
     */
    ipHeader->verHeaderLength = IP_VER + IP_IHL;
    ipHeader->qos = IP_QOS;
    ipHeader->length = stack_ntoh((p->len - FRAME_HDR_LEN));
    ipHeader->id = 0;                                                           // TODO need a proper ID schema
    ipHeader->defrag = stack_ntoh(0 | IP_FLAG_DF);
    ipHeader->ttl = IP_TTL;
    ipHeader->protocol = protocol;
    ipHeader->checksum = 0;                                                     // replace after calculating
    ipHeader->destIp = dest;                                                    // destination IP

    /* TODO if we need to insert options, then the datagram or segment data
     *    will have to be moved. right now implementation assumes no IPv4 options
     *    are needed (IHL = 5).
     */

    /* find an interface by scanning the route table for a valid network
     * that connects to 'dest', if no route found drop packet and return error
     */
    for (i = 0; i < ROUTE_TABLE_LENGTH; i++)
    {
        route = stack_get_route(i);                                             // get pointer to route record
        if ( route != NULL && (route->destNet == (dest & route->netMask)) )     // check if valid route on this network
        {
            netif = stack_get_ethif(route->netIf);                              // get pointer to the target interface
            if ( netif != NULL )
            {
                ipHeader->srcIp = netif->ip4addr;
                ipHeader->checksum = ~(stack_checksum(ipHeader, IP_HDR_LEN));   // calculate IP header checksum
                if ( netif->output )
                    result = netif->output(netif, p);                           // send the packet
            }
            else
            {
                result = ERR_NETIF;                                             // could not get network interface assigned
            }
            break;                                                              // abort the search
        }
        else
        {
            result = ERR_NO_ROUTE;
        }
    } /* end of route-table search loop */

    /* if a route was not found, select the default gateway
     * of the first interface
     */
    if ( result == ERR_NO_ROUTE )
    {
        netif = stack_get_ethif(0);                                             // TODO is this arbitrary selection a good choice?
        if ( netif != NULL )
        {
            ipHeader->srcIp = netif->ip4addr;
            ipHeader->checksum = ~(stack_checksum(ipHeader, IP_HDR_LEN));       // calculate IP header checksum
            if ( netif->output )
                result = netif->output(netif, p);                               // send the packet
        }
        else
        {
            result = ERR_NETIF;                                                 // could not get network interface assigned
        }
    }

    return result;
}

/*------------------------------------------------
 * ip4_icmp_handler()
 *
 *  ICMP request and reply handler
 *  accepts ICMP requests and responds to them
 *
 * param:  pbuf pointer of the input packet
 *         network interface the packet came from
 * return: none
 *
 */
static void ip4_icmp_handler(struct pbuf_t* const p, struct net_interface_t* const netif)
{
    struct ip_header_t  *ip_in;
    struct icmp_t       *icmp_in;
    struct ip_header_t  *ip_out;
    struct icmp_t       *icmp_out;
    struct pbuf_t       *q;
    uint16_t             ipHeaderLen;
    uint16_t             payloadLen;

    ip_in = (struct ip_header_t*) &(((struct ethernet_frame_t*)(p->pbuf))->payloadStart); // pointer to IP packet header

    ipHeaderLen = (ip_in->verHeaderLength & 0x0f) * 4;                          // calculate header length in bytes
    icmp_in = (struct icmp_t*)(((uint8_t*) ip_in) + ipHeaderLen);               // pointer to the ICMP header

    payloadLen = p->len - FRAME_HDR_LEN - ipHeaderLen - ICMP_HDR_LEN;           // calculate ICMP payload length in bytes

    switch ( stack_ntoh(icmp_in->type_code) )
    {
        case ECHO_REQ:                                                          // handle ICMP ping request by responding to it
            q = pbuf_allocate();                                                // allocate a pbuf and establish pointers
            if ( q == NULL )
                break;
            ip_out = (struct ip_header_t*) &(q->pbuf[FRAME_HDR_LEN]);
            icmp_out = (struct icmp_t*) &(ip_out->payloadStart);

            ip_out->verHeaderLength = IP_VER + IP_IHL;                          // populate reply's IP header
            ip_out->qos = IP_QOS;
            ip_out->length = stack_ntoh(IP_HDR_LEN + ICMP_HDR_LEN + payloadLen);
            ip_out->id = ip_in->id;
            ip_out->defrag = stack_ntoh(0 | IP_FLAG_DF);
            ip_out->ttl = IP_TTL;
            ip_out->protocol = IP4_ICMP;
            ip_out->checksum = 0;                                               // replace after calculating
            ip_out->srcIp = ip_in->destIp;                                      // TODO should this be netif->ip4addr?
            ip_out->destIp = ip_in->srcIp;

            icmp_out->type_code = stack_ntoh(ECHO_REPLY);                       // populate ICMP reply header
            icmp_out->checksum = 0;                                             // replace after calculating
            icmp_out->id = icmp_in->id;
            icmp_out->seq = icmp_in->seq;

            memcpy(&(icmp_out->payloadStart),
                   &(icmp_in->payloadStart),
                   payloadLen);                                                 // copy payload

            ip_out->checksum = ~(stack_checksum(ip_out, IP_HDR_LEN));           // calculate checksums
            icmp_out->checksum = ~(stack_checksum(icmp_out, ICMP_HDR_LEN + payloadLen));

            q->len = FRAME_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN + payloadLen;    // set packet length

            if ( netif->output )
                netif->output(netif, q);                                        // send the packet through the interface it came from

            pbuf_free(q);                                                       // free the transmit buffer
            break;

        case ECHO_REPLY:                                                        // we got a reply from our ICMP ping
            if ( stack.icmp_input_handler )                                     // check if ping app registered to get a response, drop otherwise
                stack.icmp_input_handler(p);
            break;

        default:;                                                               // drop everything else
    }
}

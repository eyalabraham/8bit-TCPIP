/* ***************************************************************************

  udp.c

  Code module for UDP transport protocol
  This module implements the functionality needed for UDP transport

  resources:
    http://www.cs.dartmouth.edu/~campbell/cs60/socketprogramming.html
    https://en.wikipedia.org/wiki/User_Datagram_Protocol

  May 2017 - Created

*************************************************************************** */

#include    <malloc.h>
#include    <string.h>
#include    <assert.h>

#include    "ip/udp.h"
#include    "ip/ipv4.h"
#include    "ip/stack.h"

/* -----------------------------------------
   module globals
----------------------------------------- */
struct udp_pcb_t        udpPCB[UDP_PCB_COUNT];              // UDP protocol control blocks

/* -----------------------------------------
   static functions
----------------------------------------- */
static void udp_input_handler(struct pbuf_t* const);

/*------------------------------------------------
 * udp_init()
 *
 *  initialize UDP
 *
 * param:  none
 * return: none
 *
 */
void udp_init(void)
{
    int     i;

    for (i = 0; i < UDP_PCB_COUNT; i++)                     // initialize PCB list
    {
        udpPCB[i].localIP = 0;
        udpPCB[i].localPort = 0;
        udpPCB[i].remoteIP = 0;
        udpPCB[i].remotePort = 0;
        udpPCB[i].udp_callback = NULL;
        udpPCB[i].state = FREE;
    }

    stack_set_protocol_handler(IP4_UDP, udp_input_handler); // setup the stack handler for incoming UDP packets
}

/*------------------------------------------------
 * udp_new()
 *
 *  create a UDP connection and return UDP PCB which was created.
 *  this is the first function to call before using a UDP connection.
 *  return NULL if the PCB data structure could not be allocated.
 *
 * param:  none
 * return: pointer to PCB or NULL if failed, possible out of memory for PCB (see options.h)
 *
 */
struct udp_pcb_t* udp_new(void)
{
    int     i;

    for (i = 0; i < UDP_PCB_COUNT; i++)                     // scan PCB list
    {
        if ( udpPCB[i].state == FREE )
        {
            return (struct udp_pcb_t*) &(udpPCB[i]);        // return UDP PCB address if a free one exists
        }
    }

    return NULL;                                            // return NULL if no UDP PCB is available
}

/*------------------------------------------------
 * udp_close()
 *
 *  close a UDP connection created with udp_new(), and clear its PCB
 *  this is the last function to call to close a UDP connection and free its PCB.
 *
 * param:  pointer to a valid PCB
 * return: none
 *
 */
void udp_close(struct udp_pcb_t *pcb)
{
    pcb->localIP = 0;                                       // clean PCB parameters to set as 'free'
    pcb->localPort = 0;
    pcb->remoteIP = 0;
    pcb->remotePort = 0;
    pcb->udp_callback = NULL;
    pcb->state = FREE;
}

/*------------------------------------------------
 * udp_bind()
 *
 *  bind a PCB connection to a local IP address and a port
 *  this function should be called after udp_new() and before using UDP send/receive functions
 *  TODO if port number is '0', the function will bind to first available arbitrary port number
 *
 * param:  pointer to a valid PCB, local IP 'addr' and 'port'
 * return: ERR_OK if no errors or ip4_err_t with error code
 *
 */
ip4_err_t udp_bind(struct udp_pcb_t *pcb, const ip4_addr_t addr, uint16_t port)
{
    int         i;

    for (i = 0; i < UDP_PCB_COUNT; i++)                     // scan PCB list
    {
        if ( udpPCB[i].state == FREE ||                     // skip free PCBs or this 'pcb'
             &udpPCB[i] == pcb )
            continue;

        if ( udpPCB[i].localIP == addr &&                   // check if another PCB is already bound to this local IP/port
             udpPCB[i].localPort == port)
        {
            return ERR_IN_USE;                              // exit with error if already in use
        }
    }

    pcb->localIP = addr;                                    // ok to bind
    pcb->localPort = port;
    pcb->state = BOUND;

    return ERR_OK;
}

/*------------------------------------------------
 * udp_sendto()
 *
 *  construct a UDP datagram from data in a buffer and send to a destination IP and port
 *  this function does not change the remote IP and port numbers of the PCB if these are set
 *
 * param:  a valid PCB, pointer to a data buffer and its length,
 *         destination IP 'addr' and 'port'
 * return: ERR_OK if no errors or ip4_err_t with error code
 *
 */
ip4_err_t udp_sendto(struct udp_pcb_t *pcb, uint8_t* const payload, uint16_t payloadLen, const ip4_addr_t destIP, uint16_t destPort)
{
    ip4_err_t       result = ERR_OK;
    struct udp_t   *udp;
    struct pbuf_t  *p;

    if ( payloadLen > MAX_DATAGRAM_LEN )                                            // limit on datagram size
        return ERR_MTU_EXD;

    p = pbuf_allocate();
    if ( p != NULL )
    {
        udp = (struct udp_t*) &(p->pbuf[FRAME_HDR_LEN + IP_HDR_LEN]);               // pointer to UDP header

        udp->srcPort = stack_ntoh(pcb->localPort);                                  // populate UDP header
        udp->destPort = stack_ntoh(destPort);
        udp->length = stack_ntoh(payloadLen + UDP_HDR_LEN);
        udp->checksum = 0;                                                          // not using checksum
        memcpy(&(udp->payloadStart), payload, payloadLen);                          // copy payload

        p->len = FRAME_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + payloadLen;             // set packet length
        result = ip4_output(destIP, IP4_UDP, p);                                    // transmit the UDP datagram
        pbuf_free(p);                                                               // free the transmit buffer
    }
    else
    {
        result = ERR_MEM;
    }

    return result;
}

/*------------------------------------------------
 * udp_recv()
 *
 *  registers a callback to handle received data
 *
 * param:  pointer to a valid PCB and a UDP callback handler function
 * return: ERR_OK or 'ip4_err_t' error code on error
 *
 */
ip4_err_t udp_recv(struct udp_pcb_t *pcb, udp_recv_callback udp_recv_fn)
{
    ip4_err_t       result = ERR_NOT_BOUND;

    if ( pcb->state == BOUND )
    {
        pcb->udp_callback = udp_recv_fn;
        result = ERR_OK;
    }

    return result;
}

/*------------------------------------------------
 * udp_input_handler()
 *
 *  this function links to the stack and provides a general
 *  entry point into UDP handling.
 *  This handler will be called by the stack when a UDP protocol packet is waiting
 *  for input processing. The function will parse the input packet and call
 *  the appropriate bound UDP PCB
 *
 * param:  pointer to an input pbuf
 * return: none
 *
 */
static void udp_input_handler(struct pbuf_t* const p)
{
    struct ip_header_t *ip;
    struct udp_t       *udp;
    uint16_t            ipHeaderLen;
    ip4_addr_t          addr;
    uint16_t            port;
    int                 i;

    ip = (struct ip_header_t*) &(((struct ethernet_frame_t*)(p->pbuf))->payloadStart);  // pointer to IP packet header
    ipHeaderLen = (ip->verHeaderLength & 0x0f) * 4;                                     // calculate header length in bytes
    udp = (struct udp_t*)(((uint8_t*) ip) + ipHeaderLen);                               // pointer to the UDP header

    addr = ip->destIp;                                                                  // extract destination IP and port
    port = stack_hton(udp->destPort);

    for (i = 0; i < UDP_PCB_COUNT; i++)                                                 // scan PCB list
    {
        if ( udpPCB[i].state == FREE )                                                  // skip free PCBs
            continue;

        if ( udpPCB[i].localIP == addr &&                                               // if a local IP/port is bound to the destination IP/port
             udpPCB[i].localPort == port &&
             udpPCB[i].udp_callback != NULL )                                           // and a callback is defined
        {
            udpPCB[i].udp_callback(p, ip->srcIp, udp->srcPort);                         // then invoke the callback
        }
    }
}

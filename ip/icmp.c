/* ***************************************************************************

  icmp.c

  Code module for ICMP Ping protocol
  This module implements only the functionality needed for a Ping application

  May 2017 - Created

*************************************************************************** */

#include    <malloc.h>
#include    <string.h>
#include    <assert.h>

#include    "ip/icmp.h"
#include    "ip/ipv4.h"
#include    "ip/stack.h"

/* -----------------------------------------
   module globals
----------------------------------------- */

/* -----------------------------------------
   static functions
----------------------------------------- */

/*------------------------------------------------
 * icmp_ping_output()
 *
 *  Initialize ICMP Ping response processing
 *
 * param:  pointer to Ping input call-back function
 * return: none
 *
 */
void icmp_ping_init(void (*ping_input)(struct pbuf_t* const))
{
    stack_set_protocol_handler(IP4_ICMP, ping_input);
}

/*------------------------------------------------
 * icmp_ping_output()
 *
 *  output an ICMP Ping packet
 *
 * param:  ping destination/target IP, identifier and sequence numbers,
 *         pointer to payload and its length in bytes
 * return: ERR_OK if no error, otherwise ip4_err_t error code
 *
 */
ip4_err_t icmp_ping_output(ip4_addr_t dest, uint16_t ident, uint16_t seq, uint8_t* const payload, uint8_t payloadLen)
{
    ip4_err_t       result = ERR_OK;
    struct pbuf_t  *p;
    struct icmp_t  *icmp_out;

    p = pbuf_allocate();
    if ( p != NULL )
    {
        icmp_out = (struct icmp_t*) &(p->pbuf[FRAME_HDR_LEN + IP_HDR_LEN]);         // pointer to ICMP header

        icmp_out->type_code = stack_ntoh(ECHO_REQ);                                 // populate ICMP Ping request
        icmp_out->checksum = 0;                                                     // replace after calculating
        icmp_out->id = stack_ntoh(ident);
        icmp_out->seq = stack_ntoh(seq);
        memcpy(&(icmp_out->payloadStart), payload, payloadLen);                     // copy payload
        icmp_out->checksum = ~(stack_checksum(icmp_out, ICMP_HDR_LEN + payloadLen));// calculate ICMP checksum

        p->len = FRAME_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN + payloadLen;            // set packet length

        result = ip4_output(dest, IP4_ICMP, p);                                     // transmit request

        pbuf_free(p);                                                               // free the transmit buffer
    }
    else
    {
        result = ERR_MEM;
    }

    return result;
}

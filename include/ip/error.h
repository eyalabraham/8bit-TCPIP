/* ***************************************************************************

  ip4error.h

  header file for the Ipv4 stack error codes

  May 2017 - Created

*************************************************************************** */

#ifndef __IP4ERROR_H__
#define __IP4ERROR_H__

typedef enum                        // stack wide error codes
{
    ERR_OK        =  0,             // no errors, result ok
    ERR_MEM       = -1,             // out of memory error, memory resource allocation error
    ERR_DRV       = -2,             // an interface driver error occurred, like an SPI IO problem
    ERR_NETIF     = -3,             // network interface error
    ERR_MTU_EXD   = -4,             // MTU size exceeded
    ERR_ARP_FULL  = -5,             // ARP table is full, entry not added ( or one was discarded to add this one )
    ERR_ARP_NONE  = -6,             // an ARP query or update request did not find the target IP in the table, packet not queued
    ERR_ARP_QUEUE = -7,             // the packet was queued pending destination IP address resolution
    ERR_RT_FULL   = -8,             // route table full, entry not added
    ERR_RT_RANGE  = -9,             // route table index out of range
    ERR_BAD_PROT  = -10,            // trying to send an unsupported protocol (ipv4.c)
    ERR_NO_ROUTE  = -11,            // no route to send IP packet, check routing table
    ERR_TX_COLL   = -12,            // too many transmit collisions, Tx aborter
    ERR_TX_LCOLL  = -13,            // late-collision during transmit, possible full/half-duplex mismatch
    ERR_IN_USE    = -14,            // UDP or TCP IP address and/or port are already bound to by another connection or are invalid
    ERR_NOT_BOUND = -15,            // PCB is not bound
    ERR_NOT_LSTN  = -16,            // PCB is not in listed state
    ERR_PCB_ALLOC = -17,            // could not allocate/find PCB
    ERR_TCP_CLOSING = -18,          // a command issued to a TCP connection that is in the process of closing
    ERR_TCP_CLOSED  = -19,          // a command issued to a TCP connection that is closed
    ERR_TCP_WACK  = -20             // TCP is waiting for an ACK, cannot transmit the segment
} ip4_err_t;

#endif /* __IP4ERROR_H__ */





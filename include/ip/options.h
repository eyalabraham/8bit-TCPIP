/* ***************************************************************************

  options.h

  header file for IP stack components

  May 2017 - Created

*************************************************************************** */

#ifndef __OPTIONS_H__
#define __OPTIONS_H__

/*
 * platform/compile option definitions
 *
 */
#define     SYSTEM_DOS          1           // DOS or LMTE executive environment
#define     SYSTEM_LMTE         !SYSTEM_DOS

/*
 * stack-wide definitions
 *
 */
#define     HOSTNAME_LENGTH     10
#define     HOSTNAME            "pcxt\0"

#define     RX_BUFS             1           // # of input packet buffers, relying on device driver buffering
#define     TX_BUFS             7           // # of output packet buffers
#define     ARP_QUEUE_BUFS      2           // # of queuing buffers for packets waiting for ARP resolution
#define     PACKET_BUFS         (RX_BUFS+TX_BUFS+ARP_QUEUE_BUFS)
#define     MAX_PBUFS           10          // max # of RX or TX buffers
#define     PACKET_BUF_SIZE     1536        // size of packet buffer in bytes

#define     STACK_TIMER_COUNT   4           // timers that the stack manages (minimum of 3: 1 x TCP, 2 x ARP)

/*
 * Physical layer setup options, Ethernet HW
 *
 */
#define     ETHIF_NAME_LENGTH   5
#define     ETHIF_NAME          "eth0\0"    // interface's identifier

#define     MAC0                0x00        // my old USB wifi 'B' adapter (or can use: 00:e0:63:82:4b:e9)
#define     MAC1                0x0c
#define     MAC2                0x41
#define     MAC3                0x57
#define     MAC4                0x70
#define     MAC5                0x00

#define     FULL_DUPLEX         0           // set to 0 for half-duplex setup
#define     INTERFACE_COUNT     1           // # of ethernet interfaces in the system
#define     DRV_DMA_IO          0           // set to 1 for DMA based IO

#define     MTU                 1500

/*
 * SLIP setup options
 *
 */
#define     SLIP_ONLY           1           // set to '1' if only SLIP is used with no other interface
#define     SLIP_NAME           "sl0\0"     // SLIP interface's identifier
#define     SLIP_BAUD           9600        // valid rates on NEC V25: '9600' and '19200'
                                            // valid rates on PC-XT: '4800','9600','19200','38400','57600'

/*
 * Data Link layer setup options, buffers, ARP etc
 *
 */
#define     ARP_TABLE_LENGTH    10          // number of entries in the ARP table
#define     ARP_QUEUE_LENGTH    ARP_QUEUE_BUFS
#define     ARP_QUEUE_EXPR      600         // milisec time-out value for queued packets waiting for ARP response
#define     ARP_CACHE_EXPR      300000      // 5min ARP cache expiration
/*
 * Network layer setup options
 *
 */
#define     ROUTE_TABLE_LENGTH  2           // max number of entries in the routing table, must be .gte. to INTERFACE_COUNT

/*
 * UDP options
 *
 */
#define     MAX_DATAGRAM_LEN    1472        // absolute maximum datagram length in bytes (MTU - IPv4 header - UDP header)
                                            // *** does not guarantee transmittal; if IP4 header has options, this might exceed MTU
#define     UDP_PCB_COUNT       3           // max number of concurrent open UDP connections (PCBs = protocol control block)

/*
 * TCP options
 *
 */
#define     MAX_SEGMENT_LEN     1460        // absolute maximum segment length in bytes (MTU - IPv4 header - TCP header)
                                            // *** does not guarantee transmittal; if IP4 or TCP headers have options, this might exceed MTU
#define     DEF_MSS             536         // default if not received from peer (RFC 1122 4.2.2.6  Maximum Segment Size Option: RFC-793 Section 3.1)
#define     MSS                 MAX_SEGMENT_LEN

#define     DEF_RTT             2000UL      // changes to 2[sec] because of slow CPU (was 1[sec] RFC 6298 section 2.1)
#define     TCP_MAX_RETRAN      5           // maximum number of TCP segment retransmits before reset and connection abort

#define     TCP_SERVER_COUNT    1           // number of listening servers
#define     TCP_CONN_PER_SRVR   10          // max incoming connections per server
#define     TCP_CLIENT_COUNT    0           // max outgoing client connections
#define     TCP_PCB_COUNT       (TCP_CLIENT_COUNT+TCP_SERVER_COUNT*(1+TCP_CONN_PER_SRVR))
#define     TCP_DATA_BUF_SIZE   1024        // in bytes, max 32,768 bytes in powers of 2: 2, 4, 8, 16, 32, ...
#define     TCP_DEF_WINDOW      TCP_DATA_BUF_SIZE   // bytes

#define     TCP_MSL_TIMEOUT     30000UL     // Maximum Segment Lifetime (in RFC-793 = 2 minutes)
#define     TCP_HSTATE_TIMEOUT  120000UL    // time out to exit a half open or half closed state (typical = 5min)

/*
 * general debug options
 *
 */
#define     DEBUG_ON            0           // set to '0' to turn off debug printing

#endif  /* __OPTIONS_H__ */

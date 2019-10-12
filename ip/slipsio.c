/* ***************************************************************************

  slipsio.c

   This is a SLIP Interface driver.
   It follows the LwIP SLIP driver structure, and implements
   driver support for my PC-XT Z80 SIO-2 USART board.
   The driver is self contained.

   Eyal Abraham, September 2019

*************************************************************************** */

//#define     DRV_DEBUG_FUNC_EXIT
//#define     DRV_DEBUG_FUNC_NAME
//#define     DRV_DEBUG_FUNC_PARAM

#if defined DRV_DEBUG_FUNC_EXIT || defined DRV_DEBUG_FUNC_NAME || defined DRV_DEBUG_FUNC_PARAM
#include    <stdio.h>
#endif

#include    <string.h>
#include    <malloc.h>
#include    <assert.h>
#include    <conio.h>
#include    <i86.h>
#include    <dos.h>
#include    <sys/types.h>

#include    "ip/options.h"
#include    "ip/stack.h"
#include    "ip/slip.h"

/* -----------------------------------------
   internal driver definitions
----------------------------------------- */
#define     SIODATAA        0x390
#define     SIOCMDA         0x392
#define     SIODATAB        0x391
#define     SIOCMDB         0x393
#define     BAUDGEN         0x394

#define     INT_VEC_MASK    0x0e
#define     INT_VECA_TXEMPT 0x08
#define     INT_VECA_EXT    0x0a
#define     INT_VECA_RXRDY  0x0c
#define     INT_VECA_RXERR  0x0e

#define     SIO_INT_RXCHAR  0x01
#define     SIO_INT_PENDING 0x02
#define     SIO_INT_TXEMPT  0x04
#define     SIO_RST_TX_INT  0x28
#define     SIO_RETI        0x38
#define     SIO_VEC_STATUS  0x04

#ifndef     SLIP_BAUD
#define     SLIP_BAUD       9600
#endif

#define     IRR             0x20                // interrupt request register
#define     ISR             0x20                // interrupt in service register
#define     IMR             0x21                // interrupt mask register
#define     COM2_INTR_MASK  0xf7                // b3.. (IRQ3) COM2 serial i/o

#define     SER_IRQ         0x0b                // Serial port interrupt, COM2

#define     SER_IN          4096                // circular input buffer
#define     SER_OUT         2048                // circular output buffer (not the pbuf!)

#define     SLIP_END        0xC0                // start and end of every packet
#define     SLIP_ESC        0xDB                // escape start (one byte escaped data follows)
#define     SLIP_ESC_END    0xDC                // following escape: original byte is 0xC0 (END)
#define     SLIP_ESC_ESC    0xDD                // following escape: original byte is 0xDB (ESC)

#define     PIC_EOI         0x20                // 8259 PIC
#define     PIC_OCW2        0x20

/* -----------------------------------------
   static function prototype
----------------------------------------- */
static void __interrupt __far ser_isr(void);

/* -----------------------------------------
   driver globals
----------------------------------------- */
static int sio_config[] =
    {   0x18,               // channel reset
        0x14,               // select WR4 and Ext Int reset
        0x44,               // clkx16, 1 stop bit, no parity
        0x03,               // select WR3
        0xc1,               // Rx: 8-bit, ENABLE
        0x05,               // select WR5
        0x68,               // Tx, 8-bit, ENABLE, RTS not active
        0x11,               // select WR1 and Ext Int reset
        0x10,               // enable Rx interrupts
        -1
    };

static uint8_t  recvBuffer[SER_IN];     // serial circular receive buffer
static int      recvRdPtr;
static int      recvCnt;
static int      recvWrPtr;
static int      slip_raw_packet_cnt;

static uint8_t             sendBuffer[SER_OUT]; // serial transmit buffer
static volatile uint8_t    sendInProgress;
static volatile uint16_t   txCount;
static volatile uint16_t   txPtr;

static struct slip_t       slipVar;
static int                 linkState = 0;

/* -----------------------------------------
   driver implementation
----------------------------------------- */

/* -----------------------------------------
 * slip_init()
 *
 * This function initialized the Z80 SIO-2 serial interface on the
 * PC-XT board. It is assumed that the serial interface
 * on the host will be bridged to an Ethernet device
 * example, use Linux 'slattach'
 * Serial connection parameters are set at compile time from options.h
 *
 * param:  none
 *
 * return: pointer to SLIP data structure
 *         NULL if failed
 * ----------------------------------------- */
struct slip_t* slip_init(void)
{
    uint8_t    *pBaudSelect;        // PCXT BIOS data area pointer
    uint8_t     temp;
    int         i = 0;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    /* disable interrupts
     */
    _disable();

    /* setup interrupt vector
     */
    _dos_setvect(SER_IRQ, ser_isr);

    /* Baud rate channel A initialization
        0,0,0   0  4800
        0,0,1   1  9600
        0,1,0   2  19200
        0,1,1   3  38400
        1,0,0   4  57600
     */
    pBaudSelect = MK_FP(0x0040, 0x0012);
    temp = *pBaudSelect & 0xf8;

#if ( SLIP_BAUD == 4800 )
    temp |= 0;
#elif (  SLIP_BAUD == 9600 )
    temp |= 1;
#elif (  SLIP_BAUD == 19200 )
    temp |= 2;
#elif (  SLIP_BAUD == 38400 )
    temp |= 3;
#elif (  SLIP_BAUD == 57600 )
    temp |= 4;
#endif

    *pBaudSelect = temp;
    outp(BAUDGEN, temp);

    /* setup serial interrupt receive circular buffer
     * with write pointer and count already accounting for the
     * four-byte next packet and bytes co_enableunt header
     */
    recvRdPtr = 0;
    recvWrPtr = 0;
    recvCnt = 0;
    slip_raw_packet_cnt = 0;

    sendInProgress = 0;
    txCount = 0;

    /* initialize the SLIP internal data structure
     */
    slipVar.nextPacket = 0;
    slipVar.currentLength = 0;
    
    linkState = 1;

    /* SIO-2 channel B interface initialization
     */
    outp(SIOCMDB, 1);               // select WR1
    outp(SIOCMDB, SIO_VEC_STATUS);  // enable status in interrupt vector

    /* SIO-2 channel A interface initialization
     */
    while ( sio_config[i] != -1 )
    {
        outp(SIOCMDA, (uint8_t)sio_config[i]);
        i++;
    }

    /* enable interrupt input #3
     * on the interrupt contrller
     */
    temp = inp(IMR) & COM2_INTR_MASK;
    outp(IMR, temp);

    /* enable interrupts now
     */
    _enable();

    return &slipVar;
}

/* -----------------------------------------
 * slip_close()
 *
 * This function closes the slip connection.
 * Disable interrupt on INT3 from Z80-SIO2
 *
 * param:  none
 * return: none
 * ----------------------------------------- */
void slip_close(void)
{
    uint8_t     temp;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    /* disable interrupts
     */
    _disable();

    /* disable interrupt input #3
     * on the interrupt controller
     */
    temp = inp(IMR) | ~COM2_INTR_MASK;
    outp(IMR, temp);

    /* TODO disable RX and Tx
     * TODO disable Z80-SIO2 Rx, Tx and external INT interrupts
     */

    /* enable interrupts now
     */
    _enable();
}

/* -----------------------------------------
 * slip_output()
 *
 * This function does the actual transmission of the packet.
 * The packet is contained in the pbuf that is passed to the function.
 *
 * param:  'netif' the network interface structure of the SLIP interface
 *         'p' the packet pbuf to send
 * return: ERR_OK if the packet could be sent
 *         an ip4_err_t value if the packet could not be sent
 *
 * ----------------------------------------- */
ip4_err_t slip_output(struct net_interface_t* const netif, struct pbuf_t* p)
{
    int             i;
    uint8_t         byte;
    ip4_err_t       result = ERR_OK;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    /* first copy the bytes from the pbuf buffer
     * into the transmit buffer and add SLIP ESC bytes as required.
     * when copying, skip the Ethernet header, and start from the IP packet.
     */
    txCount = 0;
    sendBuffer[txCount++] = SLIP_END;

    for ( i = FRAME_HDR_LEN; ((i < p->len) && (txCount < (SER_OUT-1))); i++ )
    {
        byte = p->pbuf[i];
        switch ( byte )
        {
            case SLIP_END:
                /* need to escape this byte (0xC0 -> 0xDB, 0xDC)
                 */
                sendBuffer[txCount++] = SLIP_ESC;
                sendBuffer[txCount++] = SLIP_ESC_END;
                break;

            case SLIP_ESC:
                /* need to escape this byte (0xDB -> 0xDB, 0xDD)
                 */
                sendBuffer[txCount++] = SLIP_ESC;
                sendBuffer[txCount++] = SLIP_ESC_ESC;
                break;

            default:
                /* normal byte - no need for escaping
                 */
                sendBuffer[txCount++] = byte;
                break;
          }
    }

    sendBuffer[txCount++] = SLIP_END;

    if ( txCount <= SER_OUT )
    {
        /* trigger the PC-XT transmit interrupt service
         * to transfer the send buffer content through the serial interface.
         * set data pointer for the interrupt routine and send the first byte
         * to trigger the send process/interrupt
         */
#ifdef DRV_DEBUG_FUNC_PARAM
    printf("  txCount %u\n", txCount);
#endif

        sendInProgress = 1;
        txPtr = 0;

        while ( txCount )
        {
            while ( (inp(SIOCMDA) & SIO_INT_TXEMPT) == 0 ) {};  // wait for Tx register to be empty
                                                                // TODO add time out
            outp(SIODATAA, sendBuffer[txPtr++]);
            txCount--;
        }

        sendInProgress = 0;
    }
    else
    {
        result = ERR_MEM;
    }

#ifdef DRV_DEBUG_FUNC_EXIT
    printf("exit: %s(%d)\n", __func__, result);
#endif

    return result;
}

/* -----------------------------------------
 * slip_input()
 *
 * allocate a pbuf and transfer the bytes of the incoming
 * packet from the interface into the pbuf.
 *
 * param:  'netif' the network interface structure of the SLIP interface
 * return: a pbuf filled with the received packet
 *         NULL on error
 *
 * ----------------------------------------- */
struct pbuf_t* const slip_input(struct net_interface_t* const netif)
{
    struct pbuf_t  *p = NULL;
    int             slipEsc = 0;

    uint16_t        len;
    uint8_t         byte;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    if ( slip_raw_packet_cnt == 0 )
        return NULL;

    assert(recvCnt);    // saninity check on byte count if slip_raw_packet_cnt > 0
    
    /* we know we have a packet so allocate a pbuf from the pool
     * and transfer the data from the raw SLIP data buffer to the pbuf.
     * Decode SLIP ESC markers while transferring data until a SLIP_END
     * is reached, which markes the end of a raw packet.
     */
    p = pbuf_allocate();

    if ( p != NULL )
    {
        /* We know we have a raw packet waiting to be ready from the SLIP buffer.
         * Read the waiting packet into a pbuf buffer and set buffer length.
         * This is an IP packet! so offset it after the Ethernet frame header
         */
        len = 0;

        while ( 1 )
        {
            byte = recvBuffer[recvRdPtr];

            recvCnt--;  // should be safe to do becasue slip_raw_packet_cnt > 0
            recvRdPtr++;
            if ( recvRdPtr == SER_IN )
                recvRdPtr = 0;

            if ( byte == SLIP_END )
            {
                break;
            }
            /* if an escape byte was read, then we need to continue
             * and get the next byte in order to evaluate the
             * resulting byte to store.
             */
            else if ( byte == SLIP_ESC )
            {
                slipEsc = 1;
            }
            /* If there is room in the pbuf store the byte in it, and
             * and convert if necessary.
             * If the pbuf is full the loop will continue to run through the remaining
             * bytes in the raw SLIP buffer until a SLIP-END is encountered.
             */
            else if ( len < (PACKET_BUF_SIZE - FRAME_HDR_LEN) )
            {
                if ( slipEsc )
                /* if previous byte read was a SLIP ESC byte
                 * reset the ESC indicator and substitute with the correct
                 * escaped byte value
                 */
                {
                    slipEsc = 0;
                    switch ( byte )
                    {
                        case SLIP_ESC_END:
                            byte = SLIP_END;
                            break;

                        case SLIP_ESC_ESC:
                            byte = SLIP_ESC;
                            break;

                        default:;
                    }
                }

                p->pbuf[FRAME_HDR_LEN + len] = byte;
                len++;
            }
        }

        slip_raw_packet_cnt--;          // completed a raw SLIP packet

        p->len = len + FRAME_HDR_LEN;   // pbuf length

#ifdef DRV_DEBUG_FUNC_PARAM
    printf("  len %u\n  recvCnt %d\n  slip_raw_packet_cnt %d\n",
               len,
               recvCnt,
               slip_raw_packet_cnt);
#endif

        /* if the frame is empty (back to back SLIP_END)
         * or larger than MTU, discard it here.
         */
        if ( len == 0 || len > MTU )
        {
            pbuf_free(p);
            return NULL;
        }
    }
#ifdef DRV_DEBUG_FUNC_PARAM
    else
    {
        printf("  *** 'pbuf' alloc err, packet dropped ***\n");
    }
#endif

    return p;
}

/* -----------------------------------------
 * slip_link_state()
 *
 * return SLIP link state.
 *
 * param:  none
 * return: '1' link is up, '0' link is down
 *         always up after initialization.
 *
 * ----------------------------------------- */
int slip_link_state(void)
{
#ifdef DRV_DEBUG_FUNC_NAME
    //printf("enter: %s()\n",__func__);
#endif

    return linkState;
}

/* -----------------------------------------
 * ser_isr()
 *
 * serial interface interrupt handler
 * will be triggered with every received
 * and transmited byte
 *
 * ----------------------------------------- */
static void __interrupt __far ser_isr(void)
{
    uint8_t     byte, int_vector;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    //_enable();  // enable interrupts during serial processing

    /* with Z80-SIO read RR2 register to get interrupt vector
     * for the reason of the interrupt.
     */

    outp(SIOCMDB, 2);                           // select RR2
    int_vector = inp(SIOCMDB) & INT_VEC_MASK;   // read RR2

    /* read the incoming bytes from the serial interface input register
     * and store in the input circular buffer if there is enough space.
     * if the buffer becomes full while reading in bytes store a SLIP END
     * and drop incoming data.
     * Data bytes are stored as-is in raw SLIP format. The routine only
     * tracks SLIP END markers and increments a global packet count that
     * are present in the buffer.
     * TODO: hardware flow control for serial link
     */
    if ( int_vector == INT_VECA_RXRDY )
    {
        byte = inp(SIODATAA);

        /* Store the incoming byte only if there is room in the buffer.
         * if not, drop the incoming bytes until the buffer is cleared.
         * This will have the effect of incomplete packets that will be dropped
         * at higher levels of the protocol. This interrupt layer needs to be
         * as fast as possible with minimal inspection.
         */
        if ( recvCnt < SER_IN )
        {
            recvBuffer[recvWrPtr] = byte;
            recvCnt++;
            recvWrPtr++;
            if ( recvWrPtr == SER_IN )
                recvWrPtr = 0;

            /* track SLIP_END markers to maintain a count of full raw SLIP
             * packets stored in the input buffer.
             */
            if ( byte == SLIP_END )
            {
                slip_raw_packet_cnt++;
            }
        }
    }

    /* end of interrupt for Z80-SIO2 USART
     */
    outp(SIOCMDA, SIO_RETI);

    /* end of interrupt for 8259 controller
     */
    outp(PIC_OCW2, PIC_EOI);
}

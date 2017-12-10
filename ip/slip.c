/* ***************************************************************************

  slip.c

   This is a SLIP Interface driver.
   It follows the LwIP SLIP driver structure, and implements
   driver support for my FlashLite v25 CPU board
   The driver is self contained.

   Eyal Abraham, November 2017

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
#include    <sys/types.h>

#include    "v25.h"

#include    "ip/options.h"
#include    "ip/stack.h"
#include    "ip/slip.h"

/* -----------------------------------------
   internal driver definitions
----------------------------------------- */
#ifndef     SLIP_BAUD
#define     SLIP_BAUD       9600
#endif

#define     SER1CTRL_2      2                   // base rate Fclk/512
#define     SER1BAUD_9600   130                 // BAUD rate divisor
#define     SER1BAUD_19200  65

#define     SER1CTRL_1      1
#define     SER1BAUD_38400  65

#define     SER1MODE        0xc9                // 8 bit, 1 start, 1 stop, no parity

#define     SER1_RX_IRQ     17                  // serial 1 receive IRQ vector number
#define     SER1RXINT       0x07                // serial 1 Rx interrupt control

#define     SER1_TX_IRQ     18                  // serial 1 transmit IRQ vector number
#define     SER1TXINT       0x07                // serial 1 Tx interrupt control, with macro service
#define     ENA_INT         0x40                // enable interrupt bit mask

#define     SER_IN          4096                // circular input buffer (1, 2, 4, or 8K)
#define     CIRC_BUFF_MASK  ((uint16_t)(SER_IN - 1))
#define     SER_OUT         1536                // circular output buffer (not the pbuf!)

#define     SLIP_END        0xC0                // start and end of every packet
#define     SLIP_ESC        0xDB                // escape start (one byte escaped data follows)
#define     SLIP_ESC_END    0xDC                // following escape: original byte is 0xC0 (END)
#define     SLIP_ESC_ESC    0xDD                // following escape: original byte is 0xDB (ESC)

/* -----------------------------------------
   static function prototype
----------------------------------------- */
static void _interrupt ser1RXisr(void);
static void _interrupt ser1TXisr(void);

/* -----------------------------------------
   driver globals
----------------------------------------- */
struct SFR              *pSfr;                  // v25 CPU IO bank pointer
struct macroChannel_tag *pMacro;

uint8_t             recvBuffer[SER_IN];         // serial circular receive buffer
volatile uint16_t   recvRdPtr;
volatile uint16_t   recvCnt;
volatile uint16_t   recvWrPtr;
volatile uint16_t   recvLastPctStart;
volatile uint16_t   recvPacketCnt;
volatile uint8_t    slipEsc;
volatile uint16_t   recvPctByteCnt;

uint8_t             sendBuffer[SER_OUT];        // serial transmit buffer
volatile uint8_t    sendInProgress;
volatile uint16_t   txCount;
volatile uint16_t   txPtr;

struct slip_t       slipVar;

int                 linkState = 0;

/* -----------------------------------------
   driver implementation
----------------------------------------- */

/* -----------------------------------------
 * slip_init()
 *
 * This function initialized the SER-1 interface on the
 * FlashLite v25 board. It is assumed that the serial interface
 * on the host will be bridged to an Ethernet device
 * example, use Linux 'slattach'
 * Serial connection parameters are set an compile time from options.h
 *
 * param:  none
 *
 * return: pointer to SLIP data structure
 *         NULL if failed
 * ----------------------------------------- */
struct slip_t* slip_init(void)
{
    uint16_t       *wpVector;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    pSfr = MK_FP(0xf000, 0xff00);

    /* serial-1 interface initialization on FlashLite V25 board
     */
    pSfr->scm1 = SER1MODE;

#if ( SLIP_BAUD == 19200 )
    pSfr->scc1 = SER1CTRL_2;
    pSfr->brg1 = SER1BAUD_19200;
#else
    pSfr->scc1 = SER1CTRL_2;
    pSfr->brg1 = SER1BAUD_9600;
#endif

    /* setup serial interrupt for receive circular buffer
     * with write pointer and count already accounting for the
     * four-byte next packet and bytes count header
     */
    recvRdPtr = 0;
    recvWrPtr = 4;
    recvCnt = 4;
    recvLastPctStart = 0;
    recvPacketCnt = 0;
    slipEsc = 0;
    recvPctByteCnt = 0;

    /* setup interrupt and macro service for transmit
     */
    sendInProgress = 0;
    txCount = 0;

    wpVector      = MK_FP(0, (SER1_TX_IRQ * 4));
    *wpVector++   = FP_OFF(ser1TXisr);
    *wpVector     = FP_SEG(ser1TXisr);

    pSfr->stic1 = SER1TXINT;

    /* setup receive interrupt vectors
     */
    wpVector      = MK_FP(0, (SER1_RX_IRQ * 4));
    *wpVector++   = FP_OFF(ser1RXisr);
    *wpVector     = FP_SEG(ser1RXisr);

    pSfr->sric1 = SER1RXINT;

    /* initialize the SLIP internal data structure
     */
    slipVar.nextPacket = 0;
    slipVar.currentLength = 0;
    
    linkState = 1;

    return &slipVar;
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
    struct slip_t  *slip_priv;
    ip4_err_t       result = ERR_OK;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    slip_priv = (struct slip_t*)netif->state;
    
    /* check if the transmission of the previous packet
     * has completed, wait here if not.
     * TODO should use some time out value?
     */
    while ( sendInProgress ) {};

    /* first copy the bytes from the pbuf buffer
     * into the transmit buffer and add SLIP ESC bytes as required.
     * when copying, skip the Ethernet header, and start from the IP packet.
     */
    for ( i = FRAME_HDR_LEN; ((i < p->len) && (txCount < SER_OUT)); i++ )
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

#ifdef DRV_DEBUG_FUNC_PARAM
    printf("  txCount %u\n",txCount);
#endif

    if ( txCount < SER_OUT )
    {
        /* start the NEC v25 CPU interrupt service
         * to transfer the send buffer content through the
         * serial-1 interface
         * set pointer for the interrupt routine and send the first byte
         * to trigger the send process/interrupt
         */
        sendInProgress = 1;

        txPtr = 0;
        pSfr->txb1 = sendBuffer[0];
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
    struct pbuf_t  *p;
    uint16_t        len;
    uint16_t        i;
    struct slip_t  *slip_priv;

    if ( recvPacketCnt == 0 )
        return NULL;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    slip_priv = (struct slip_t*)netif->state;
    
    /* update read pointer to point to next packet read address start,
     * current packet length into 'slip_priv'.
     * then read received packet data.
     */
    recvRdPtr = slip_priv->nextPacket;

    i = (uint16_t)recvBuffer[recvRdPtr++];
    recvRdPtr &= CIRC_BUFF_MASK;
    i |= (uint16_t)recvBuffer[recvRdPtr++] << 8;
    recvRdPtr &= CIRC_BUFF_MASK;
    slip_priv->nextPacket = i;

    i = (uint16_t)recvBuffer[recvRdPtr++];
    recvRdPtr &= CIRC_BUFF_MASK;
    i |= (uint16_t)recvBuffer[recvRdPtr++] << 8;
    recvRdPtr &= CIRC_BUFF_MASK;
    slip_priv->currentLength = i;

#ifdef DRV_DEBUG_FUNC_PARAM
    printf("  len %u\n next 0x%04x\n rdPt 0x%04x\n  pkt %u\n",
               slip_priv->currentLength,
               slip_priv->nextPacket,
               recvRdPtr,
               recvPacketCnt);
#endif

    /* obtain the size of the packet and put it into the 'len' variable
     * also check if 'len' is zero or larger than MTU.
     * if it is zero the exit because this was a back to back SLIP END character.
     *
     * reduce 'recvCnt' by the packet length plus the 4 header bytes
     * doing this here also discards the packet if a pbuf allocation error
     *
     * TODO this is dangerous! a mistake in increasing and decreasing 'recvCnt'
     * can result in the uint16 wrapping around.
     * should be change 'recvCnt' to an 'int' and check/assert() for negative?
     * another option is to assert on 'recvCnt' that is larger then SER_IN
     * buffer size. for such a small buffer size, anything larger would
     * most probably be cause by a warp around right after the subtraction.
     */
    len = slip_priv->currentLength;

    recvPacketCnt--;

    recvCnt -= (len + 4);
    assert(recvCnt<=SER_IN);

    if ( len == 0 || len > MTU )
    {
        return NULL;
    }

    /* we know we have a packet so allocate a pbuf from the pool
     * and transfer the data to it before returning a pointer to
     * this allocated pbuf.
     * if pbuf allocation is successful then transfer the data to it.
     * complete the input by adjusting the number of bytes remaining in
     * the buffer.
     */
    p = pbuf_allocate();

    if ( p != NULL )
    {
        /* read the waiting packet into the pbuf buffer and set buffer length.
         * this is an IP packet! so offset it after the Ethernet frame header
         */
        for ( i = 0; i < len; i++ )
        {
            p->pbuf[FRAME_HDR_LEN + i] = recvBuffer[recvRdPtr++];
            recvRdPtr &= CIRC_BUFF_MASK;
        }
        p->len = len + FRAME_HDR_LEN;
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
    return linkState;
}

/* -----------------------------------------
 * ser1RXisr()
 *
 * serial interface #1 interrupt handler
 * will be triggered with every received byte
 *
 * ----------------------------------------- */
static void _interrupt ser1RXisr(void)
{
    uint8_t                     byte;

    /* read the incoming bytes from the serial interface input register
     * and store in the input circular buffer if there is enough space.
     * if the buffer becomes full while reading in a packet, flag the buffer
     * as full but keep monitoring the incoming byte stream.
     * once an end-of-packet is received reset the write pointer to the last
     * packet start position effectively discarding the last packet.
     * while reading in data bytes convert the SLIP_END and ESC state bytes to
     * proper data bytes and store in the buffer.
     * when a packet is successfully stored, build a four bytes header that
     * contains the next packet start index and the length of the last
     * read packet (like the ENC28J60 format), then increment the received packet count.
     */
    byte = pSfr->rxb1;

    /* first check is if the buffer is full then if a SLIP END was received.
     * if the receive buffer is full and not an END character exit and drop the input byte.
     * however, if a SLIP END byte is received reset the circular
     * buffer and discard any partial packet already stored
     */
    if ( recvCnt >= SER_IN )
    {
        if ( byte == SLIP_END )
        {
            recvCnt -= recvPctByteCnt;
            recvPctByteCnt = 0;
            recvWrPtr = recvLastPctStart + 4;
            recvWrPtr &= CIRC_BUFF_MASK;
        }
    }
    /* get here or to the checks below if there is space in the buffer.
     * this first test checks for an end of packet byte, and stores
     * the index to start of next packet and the numbers or bytes
     * of the last packet that just ended.
     */
    else if ( byte == SLIP_END )
    {
        /* when an end of packet was detected, write the next packet's
         * read index and the byte count of the current packet.
         * these 4 bytes go before the actual packet data bytes,
         * similar to the schema used by ENC28J60 receive buffer
         */
        recvBuffer[recvLastPctStart++] = (uint8_t)(recvWrPtr);
        recvLastPctStart &= CIRC_BUFF_MASK;
        recvBuffer[recvLastPctStart++] = (uint8_t)(recvWrPtr >> 8);
        recvLastPctStart &= CIRC_BUFF_MASK;
        recvBuffer[recvLastPctStart++] = (uint8_t)(recvPctByteCnt);
        recvLastPctStart &= CIRC_BUFF_MASK;
        recvBuffer[recvLastPctStart++] = (uint8_t)(recvPctByteCnt >> 8);
        recvLastPctStart &= CIRC_BUFF_MASK;

        /* move last packet pointer to the next packet location
         * to prepare for another packet input. also increment packet count
         * to indicate the packet we just finished storing.
         */
        recvLastPctStart = recvWrPtr;
        recvPacketCnt++;
        recvPctByteCnt = 0;

        /* this should be safe to do because as long as 'recvCnt'
         * is greater or equal to buffer size we cannot store any data
         */
        recvWrPtr += 4;
        recvWrPtr &= CIRC_BUFF_MASK;
        recvCnt += 4;
    }
    /* if an escape byte was read, then we need to exit and get the next byte
     * in order to evaluate the resulting byte to store
     */
    else if ( byte == SLIP_ESC )
    {
            slipEsc = 1;
    }
    /* evaluate an escaped byte of just store the data bytes that
     * was just read. at this point we already know that there is space in the buffer
     * so no need to check again.
     */
    else
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

        /* write the resulting byte into the circular buffer
         * if there is enough room for it, otherwise
         * signal a buffer full condition
         */
        recvBuffer[recvWrPtr] = byte;
        recvWrPtr++;
        recvWrPtr &= CIRC_BUFF_MASK;
        recvCnt++;
        recvPctByteCnt++;
    }

    /* end of interrupt epilogue for NEC V25
     */
    __asm { db  0x0f
            db  0x92
          }
}

/* -----------------------------------------
 * ser1TXisr()
 *
 * serial interface #1 interrupt handler
 * will be triggered at the completion of
 * transmitting each data byte
 * the routing will transmit the next byte
 * upon the next interrupt until all bytes
 * are sent.
 *
 * ----------------------------------------- */
static void _interrupt ser1TXisr(void)
{
    txCount--;

    if ( txCount > 0 )
    {
        txPtr++;
        pSfr->txb1 = sendBuffer[txPtr];
    }
    else
    {
        sendInProgress = 0;
    }

    /* end of interrupt epilogue for NEC V25
     */
    __asm { db  0x0f
            db  0x92
          }
}

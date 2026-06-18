/* ***************************************************************************

  slip16550.c

   This is a SLIP Interface driver.
   It follows the LwIP SLIP driver structure, and implements
   driver support for my PC-XT 16550 (and 82C50) UART.
   The driver is self contained.

   Eyal Abraham, April 2026

*************************************************************************** */

//#define     DRV_DEBUG_FUNC_EXIT
//#define     DRV_DEBUG_FUNC_NAME
//#define     DRV_DEBUG_FUNC_PARAM

#if defined DRV_DEBUG_FUNC_EXIT || defined DRV_DEBUG_FUNC_NAME || defined DRV_DEBUG_FUNC_PARAM
#include    <stdio.h>
#endif

#include    <string.h>
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
#define     UART_BASE       0x3f8

#define     UART_RBR        UART_BASE
#define     UART_THR        UART_BASE
#define     UART_IER        (UART_BASE+1)
#define     UART_IIR        (UART_BASE+2)
#define     UART_FCR        (UART_BASE+2)   // 16550 only (write)
#define     UART_LCR        (UART_BASE+3)
#define     UART_MCR        (UART_BASE+4)
#define     UART_LSR        (UART_BASE+5)
#define     UART_MSR        (UART_BASE+6)
#define     UART_SCR        (UART_BASE+7)
#define     UART_DIV_LOW    UART_BASE       // with DLAB bit set
#define     UART_DIV_HIGH   (UART_BASE+1)   // with DLAB bit set

#define     UART_IER_IE     0x01            // Rx interrupt byte available

#define     UART_IIR_PEND   0x01
#define     UART_IIR_ERR    0x06
#define     UART_IIR_RXD    0x04
#define     UART_IIR_TOV    0x0c
#define     UART_IIR_TXD    0x02
#define     UART_IIR_CTS    0x00

#define     UART_LCR_INIT   0x03            // Initialization 8N1
#define     UART_LCR_DLAB   0x80

#define     UART_MCR_RTS    0x02

#define     UART_LSR_RXD    0x01
#define     UART_LSR_ERR    0x0e            // Framing or Parity or Overrun errors
#define     UART_LSR_THRE   0x20
#define     UART_LSR_TEMT   0x40

#define     UART_MSR_CTS    0x10

#define     UART_DIV_4800   64              // BAUD divisor low byte for 4.9152MHz oscillator
#define     UART_DIV_9600   32
#define     UART_DIV_19200  16

#ifndef     SLIP_BAUD
#define     SLIP_BAUD       9600
#endif

#define     IRR             0x20            // interrupt request register
#define     ISR             0x20            // interrupt in service register
#define     IMR             0x21            // interrupt mask register
#define     COM1_INTR_MASK  0xef            // b4.. (IRQ4) COM1 serial i/o

#define     SER_IRQ         0x0c            // Serial port interrupt IRQ4, COM1

#define     SER_IN          4096            // circular input buffer
#define     SER_OUT         2048            // circular output buffer (not the pbuf!)

#define     SLIP_END        0xc0            // start and end of every packet
#define     SLIP_ESC        0xdb            // escape start (one byte escaped data follows)
#define     SLIP_ESC_END    0xdc            // following escape: original byte is 0xC0 (END)
#define     SLIP_ESC_ESC    0xdd            // following escape: original byte is 0xDB (ESC)

#define     PIC_EOI         0x20            // 8259 PIC
#define     PIC_OCW2        0x20

/* -----------------------------------------
   static function prototype
----------------------------------------- */
static void __interrupt __far ser_isr(void);

/* -----------------------------------------
   driver globals
----------------------------------------- */
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
    uint8_t     temp;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    /* disable interrupts
     */
    _disable();

    /* setup interrupt vector
     */
    _dos_setvect(SER_IRQ, ser_isr);

    /* setup serial interrupt receive circular buffer
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

    /* UARTBAUD rate
     */
    outp(UART_LCR, UART_LCR_DLAB);
    outp(UART_DIV_HIGH, 0);

#if (SLIP_BAUD==4800)
    outp(UART_DIV_LOW, UART_DIV_4800);
#elif (SLIP_BAUD==9600)
    outp(UART_DIV_LOW, UART_DIV_9600);
#elif (SLIP_BAUD==19200)
    outp(UART_DIV_LOW, UART_DIV_19200);
#else
    #error "Missing a valid BAUD rate definition in SLIP_BAUD"
#endif

    /* UART bits, parity and stop 8N1
     */
    outp(UART_LCR, UART_LCR_INIT);

    /* UART interrupt enable
     */
    outp(UART_IER, UART_IER_IE);

    /* enable interrupt
     * on the interrupt controller
     */
    temp = inp(IMR) & COM1_INTR_MASK;
    outp(IMR, temp);

    /* enable interrupts now
     */
    _enable();

    /* signal serial receive ready
     */
#if ( SLIP_HW_FLOW_CTRL == 1 )
    temp = inp(UART_MCR) | UART_MCR_RTS;
    outp(UART_MCR, temp);
#endif

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

    /* signal serial receive off-line
     */
#if ( SLIP_HW_FLOW_CTRL == 1 )
    temp = inp(UART_MCR) & ~UART_MCR_RTS;
    outp(UART_MCR, temp);
#endif

    /* disable interrupts
     */
    _disable();

    /* disable interrupt input
     * on the interrupt controller
     */
    temp = inp(IMR) | ~COM1_INTR_MASK;
    outp(IMR, temp);

    /* disable RX and Tx interrupts
     */
    temp = inp(UART_IER) & ~UART_IER_IE;
    outp(UART_IER, temp);

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

    /* is the receiver ready to accept packets
     */
#if ( SLIP_HW_FLOW_CTRL == 1 )
    if ( inp(UART_MSR) & UART_MSR_CTS == 0 )
    {
        return ERR_DRV;
    }
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
        /* TODO this function is currently a blocking function.
         *   trigger the PC-XT transmit interrupt service
         *   to transfer the send buffer content through the serial interface.
         *   set data pointer for the interrupt routine and send the first byte
         *   to trigger the send process/interrupt
         */
#ifdef DRV_DEBUG_FUNC_PARAM
    printf("  txCount %u\n", txCount);
#endif

        sendInProgress = 1;
        txPtr = 0;

        while ( txCount )
        {
            while ( (inp(UART_LSR) & UART_LSR_THRE) == 0 ) {};  // wait for Tx register to be empty
                                                                // TODO add time out
            outp(UART_THR, sendBuffer[txPtr++]);
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

    assert(recvCnt);    // sanity check on byte count if slip_raw_packet_cnt > 0
    
    /* we know we have a packet so allocate a pbuf from the pool
     * and transfer the data from the raw SLIP data buffer to the pbuf.
     * Decode SLIP ESC markers while transferring data until a SLIP_END
     * is reached, which marks the end of a raw packet.
     */
    p = pbuf_allocate();

    if ( p != NULL )
    {
        /* We know we have a raw packet waiting to be read from the SLIP buffer.
         * Read the waiting packet into a pbuf buffer and set buffer length.
         * This is an IP packet! so offset it after the Ethernet frame header
         */
        len = 0;

        while ( 1 )
        {
            byte = recvBuffer[recvRdPtr];

            recvCnt--;  // should be safe to do because slip_raw_packet_cnt > 0
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
 * will be triggered with received byte
 *
 * ----------------------------------------- */
static void __interrupt __far ser_isr(void)
{
    uint8_t     byte;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    //_enable();  // enable interrupts during serial processing?

    /* signal serial receive off-line
     */
#if ( SLIP_HW_FLOW_CTRL == 1 )
    byte = inp(UART_MCR) & ~UART_MCR_RTS;
    outp(UART_MCR, byte);
#endif

    byte = inp(UART_RBR);

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

    /* end of interrupt for 8259 controller
     */
    outp(PIC_OCW2, PIC_EOI);

    /* signal serial receive on-line
     */
#if ( SLIP_HW_FLOW_CTRL == 1 )
    byte = inp(UART_MCR) | UART_MCR_RTS;
    outp(UART_MCR, byte);
#endif
}

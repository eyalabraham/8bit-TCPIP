/* ***************************************************************************

  plip.c

   PLIP interface driver implementing PLIP Mode 0 transfer protocol.

   Resources:
    https://www.kernel.org/doc/html/v6.0/networking/plip.html
    https://gitlab.utc.fr/mi11/linux/linux-raspberrypi/-/blob/raspberrypi-kernel_1.20210108.master-1/drivers/net/plip/plip.c?ref_type=tags
    https://www.linux.it/~rubini/docs/plip/plip.html 

   Requires a Parallel Transfer Mode 0 Cable:

                A -> B          A -> B
    D0->ERROR   2 - 15          15 - 2
    D1->SLCT    3 - 13          13 - 3
    D2->PAPOUT  4 - 12          12 - 4
    D3->ACK     5 - 10          10 - 5
    D4->BUSY    6 - 11          11 - 6

                A <-> B
    GROUND      25 - 25
    -- All other pins a NOT connected

   Eyal Abraham, June 2026

*************************************************************************** */

//#define     DRV_DEBUG_FUNC_EXIT
//#define     DRV_DEBUG_FUNC_NAME
//#define     DRV_DEBUG_FUNC_PARAM

#if defined DRV_DEBUG_FUNC_EXIT || defined DRV_DEBUG_FUNC_NAME || defined DRV_DEBUG_FUNC_PARAM
#include    <stdio.h>
#endif
#include    <stdio.h>

#include    <string.h>
#include    <assert.h>
#include    <conio.h>
#include    <i86.h>
#include    <dos.h>
#include    <sys/types.h>

#include    "ip/options.h"
#include    "ip/stack.h"
#include    "ip/plip.h"

/* -----------------------------------------
   Internal driver definitions
----------------------------------------- */
#define     PARPORT_BASE    0x278

#define     PARPORT_DATA    PARPORT_BASE    // Parallel port IO addresses
#define     PARPORT_STAT    (PARPORT_BASE+1)
#define     PARPORT_CTRL    (PARPORT_BASE+2)

#define     ISR             0x20            // Interrupt in service register (OCW2)
#define     IMR             0x21            // Interrupt mask register (OCW1)

#define     EOI             0x20            // EOI signal 8259 PIC
#define     PARP_CTRL_INT   0x10            // Enable IRQ via ACK b.4 in Parallel Port control register
#define     PARP_INTR_MASK  0x80            // 8259 PIC b7.(IRQ7)
#define     PARPORT_IRQ     0x0f            // Parallel port interrupt IRQ7 vector

#define     PARPORT_ST_MASK 0xf8            // Status port bit mask
#define     PARPORT_IDLE    0x80            // Status is all '0'

#define     PLIP_TX_TRIG    0x08            // Transmission-start "header" byte
#define     PLIP_RX_ACK     0x08            // Rx Ack to Transmission-start Ack
#define     PLIP_TX_ACK     0x01            // Transmission-start Ack
#define     PLIP_NIB_STROBE 0x10            // Data.4 nibble Strobe bit (Data reg)
#define     PLIP_NIB_ACK    0x80            // Status.7 nibble Ack bit (Status reg)
#define     PLIP_NIB_SHFTR  3               // Shift to normalize low input nibble (Status reg)
#define     PLIP_NIB_SHFTL  1               // Shift to normalize high input nibble (Status reg)

#define     TIME_OUT_COUNT  100             // Wait loop count before time-out
#define     BYTE_IN         4096            // Circular receiver buffer

/* -----------------------------------------
   Static function prototype
----------------------------------------- */
static int  send_byte(uint8_t byte);
static int  receive_byte(uint8_t* byte);
static void __interrupt __far parport_isr(void);

/* -----------------------------------------
   Driver globals
----------------------------------------- */
volatile static int plip_packet_cnt;

static uint8_t  recv_buffer[BYTE_IN];        // Circular receive buffer
static uint16_t recv_rd_ptr;
static uint16_t recv_wr_ptr;
volatile static uint16_t    free_cap;

static struct plip_t    plip_var;
static int              link_state = 0;

/* -----------------------------------------
   Driver implementation
----------------------------------------- */

/* -----------------------------------------
 * plip_init()
 *
 * This function initialized the parallel port interface on the
 * PC-XT. It is assumed that the parallel port interface
 * on the host will be bridged to an Ethernet device
 * example with a plip driver.
 *
 * param:  none
 * return: pointer to PLIP data structure
 *         NULL if failed
 * ----------------------------------------- */
struct plip_t* plip_init(void)
{
    uint8_t     temp;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    /* Disable interrupts
     */
    _disable();

    /* Setup interrupt vector
     */
    _dos_setvect(PARPORT_IRQ, parport_isr);

    /* Setup interrupt receive circular buffer
     */
    recv_rd_ptr = 0;
    recv_wr_ptr = 0;
    plip_packet_cnt = 0;
    free_cap = BYTE_IN;

    /* Initialize the PLIP internal data structure
     */
    plip_var.nextPacket = 0;
    plip_var.currentLength = 0;
    
    /* Parallel port initialization
     */
    outp(PARPORT_DATA, 0);
    outp(PARPORT_CTRL, PARP_CTRL_INT);

    /* Enable interrupt
     * on the interrupt controller
     */
    temp = inp(IMR) & ~PARP_INTR_MASK;
    outp(IMR, temp);

    link_state = 1;

    /* Enable interrupts now
     */
    _enable();

    return &plip_var;
}

/* -----------------------------------------
 * plip_close()
 *
 * This function closes the plip connection
 * and disable interrupts.
 *
 * param:  none
 * return: none
 * ----------------------------------------- */
void plip_close(void)
{
    uint8_t     temp;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    /* Disable interrupts
     */
    _disable();

    /* Disable Ack line interrupts
     * and clead data port
     */
    outp(PARPORT_DATA, 0);
    outp(PARPORT_CTRL, 0);

    /* Disable interrupt on the
     * interrupt controller
     */
    temp = inp(IMR) | PARP_INTR_MASK;
    outp(IMR, temp);

    /* Enable interrupts now
     */
    _enable();
}

/* -----------------------------------------
 * plip_output()
 *
 * This function does the actual transmission of the packet.
 * The packet is contained in the pbuf that is passed to the function.
 *
 * param:  'netif' the network interface structure of the PLIP interface
 *         'p' the packet pbuf to send
 * return: ERR_OK if the packet could be sent
 *         an ip4_err_t value if the packet could not be sent
 *
 * ----------------------------------------- */
ip4_err_t plip_output(struct net_interface_t* const netif, struct pbuf_t* p)
{
    int         i;
    uint8_t     byte;
    uint8_t     check_sum = 0;
    uint16_t    count;  // Used for both time-out count and byte count.
    ip4_err_t   result = ERR_OK;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    /* PLIP transmit processing:
     *  1. Check initial port status bits in idle
     *  2. Disable ineterrputs on Ack line (Ctrl.4=0)
     *  3. Send header nibble '0x08' (Data.3=1)
     *  4. Wait (poll) for Ack (Status.6=1)
     *  5. Send count-low byte
     *  6. Send count-high byte
     *  7. ... send data bytes
     *     ... calculate running checksum (with count bytes?)
     *  8. Send checksum byte
     *  9. Reenable interrupt on Ack line (Ctrl.4=1)
     * 
     */

    /* Initial state check (needed?)
     */
    while ( (inp(PARPORT_STAT) & PARPORT_ST_MASK) != PARPORT_IDLE )
    {
        /* TODO: time-out check here */
    }
    
    /* Disable interrupts on the Ack line and start PLIP
     */
    outp(PARPORT_CTRL, 0);

    outp(PARPORT_DATA, PLIP_TX_TRIG);

    /* Wait for receiver to acknowledge
     */
    count = TIME_OUT_COUNT;
    while ( (inp(PARPORT_STAT) & PLIP_RX_ACK) == 0 )
    {
        if ( --count == 0 )
        {
            result = ERR_NETIF_TO;
            goto ABORT_PLIP_OUT;
        }
    }

    /* Send packet length
     */
    count = p->len;
    if ( send_byte((uint8_t)(count & 0x00ff)) != 0 )
    {
        result = ERR_NETIF_TO;
        goto ABORT_PLIP_OUT;
    }
    if ( send_byte((uint8_t)((count >> 8) & 0x00ff)) != 0 )
    {
        result = ERR_NETIF_TO;
        goto ABORT_PLIP_OUT;
    }

    /* Transmit frame buffer content
     */
    for ( i = 0; i < count; i++ )
    {
        byte = p->pbuf[i];
        check_sum += byte;

        if ( send_byte(byte) != 0 )
        {
            result = ERR_NETIF_TO;
            goto ABORT_PLIP_OUT;
        }
    }

#ifdef DRV_DEBUG_FUNC_PARAM
    printf("  count %u\n", count);
#endif

    if ( send_byte(check_sum) != 0 )
    {
        result = ERR_NETIF_TO;
        goto ABORT_PLIP_OUT;
    }

ABORT_PLIP_OUT:

#ifdef DRV_DEBUG_FUNC_EXIT
    printf("exit: %s(%d)\n", __func__, result);
#endif

    outp(PARPORT_DATA, 0);
    outp(PARPORT_CTRL, PARP_CTRL_INT);

    return result;
}

/* -----------------------------------------
 * plip_input()
 *
 * Allocate a pbuf and transfer the bytes of the incoming
 * packet from the interface into the pbuf.
 *
 * param:  'netif' the network interface structure of the PLIP interface
 * return: a pbuf filled with the received packet
 *         NULL on error
 *
 * ----------------------------------------- */
struct pbuf_t* const plip_input(struct net_interface_t* const netif)
{
    struct pbuf_t  *p = NULL;

    int         i;
    uint16_t    packet_len;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    if ( plip_packet_cnt == 0 )
        return NULL;
  
    /* We know we have a packet so allocate a pbuf from the pool
     * and transfer the data from the raw PLIP data buffer to the pbuf.
     */
    p = pbuf_allocate();

    /* Read the waiting packet into a pbuf buffer and set buffer length.
     */
    if ( p != NULL )
    {
        /* Low byte of length
         */
        packet_len = recv_buffer[recv_rd_ptr++];
        if ( recv_rd_ptr == BYTE_IN )
            recv_rd_ptr = 0;

        /* High byte of length
         */
        packet_len += (recv_buffer[recv_rd_ptr++] << 8);
        if ( recv_rd_ptr == BYTE_IN )
            recv_rd_ptr = 0;

        /* Copy packet to the pbuf, then set
         * pbuf length and decrement waiting packet count.
         * 'recv_rd_ptr' should point to next packet
         * starting point.
         */
        for ( i = 0; i < packet_len; i++ )
        {
            p->pbuf[i] = recv_buffer[recv_rd_ptr++];
            if ( recv_rd_ptr == BYTE_IN )
                recv_rd_ptr = 0;
        }

        plip_packet_cnt--;
        free_cap += (packet_len + 2);
        p->len = packet_len;

#ifdef DRV_DEBUG_FUNC_PARAM
        printf("  packet_len %u\n  plip_packet_cnt %d\n",
                packet_len,
                plip_packet_cnt);
#endif

        /* If the frame is empty or larger than MTU,
         * discard it here.
         */
        if ( packet_len == 0 || packet_len > MTU )
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
 * plip_link_state()
 *
 * Return PLIP link state.
 *
 * param:  none
 * return: '1' link is up, '0' link is down
 *         always up after initialization.
 *
 * ----------------------------------------- */
int plip_link_state(void)
{
#ifdef DRV_DEBUG_FUNC_NAME
    //printf("enter: %s()\n",__func__);
#endif

    return link_state;
}

/* -----------------------------------------
 * send_byte()
 *
 *  Send a byte (octet) through the parallel port
 *  following PLIP protocol.
 * 
 * Each byte sent as two (2) nibbles:
 * NOTE: Status.7 is the inverted input /BUSY connected to Data.4 output
 *  1. <send 0x10+(byte & 0x0F)>        <wait for rx. '0x0?' Status.7=0>
 *  2. <send 0x00+((byte >> 4) & 0x0F)> <wait for rx. '0x8?' Status.7=1>
 *
 * param:  Byte to send
 * return: Send ok=0, time-out/error=(-1)
 *
 * ----------------------------------------- */
static int send_byte(uint8_t byte)
{
    register uint8_t    temp_byte;
    register uint16_t   time_out_count;

    /* Transmit low nibble and wait for Ack=1
     */
    temp_byte = (byte & 0x0f);
    outp(PARPORT_DATA, temp_byte);
    temp_byte |= PLIP_NIB_STROBE;
    outp(PARPORT_DATA, temp_byte);

    time_out_count = TIME_OUT_COUNT;
    while ( (inp(PARPORT_STAT) & PLIP_NIB_ACK) )
    {
        if ( --time_out_count == 0 )
            return -1;
    }

    /* Transmit high nibble and wait for Ack=0
     */
    temp_byte = ((byte >> 4) & 0x0f) | PLIP_NIB_STROBE;
    outp(PARPORT_DATA, temp_byte);
    temp_byte &= ~PLIP_NIB_STROBE;
    outp(PARPORT_DATA, temp_byte);

    time_out_count = TIME_OUT_COUNT;
    while ( (inp(PARPORT_STAT) & PLIP_NIB_ACK) == 0 )
    {
        if ( --time_out_count == 0 )
            return -1;
    }

    return 0;
}

/* -----------------------------------------
 * receive_byte()
 *
 *  Receive a byte (octet) from the parallel port
 *  following PLIP protocol.
 * 
 * Each byte sent as two (2) nibbles:
 *  1. <wait for rx. '0x1?' Status.4=1>   <send 0x10+(byte & 0x0F)>
 *  2. <wait for rx. '0x0?' Status.4=0>   <send 0x00+((byte >> 4) & 0x0F)>
 *
 * param:  Pointer to byte received
 * return: Send ok=0, time-out/error=(-1)
 *
 * ----------------------------------------- */
static int receive_byte(uint8_t* byte)
{
    uint8_t    temp_byte;
    uint16_t   time_out_count;

    /* Wait for line /BUSY=1 (Status.7=0) and receive low nibble
     */
    time_out_count = TIME_OUT_COUNT;
    while ( ((temp_byte = inp(PARPORT_STAT)) & PLIP_NIB_ACK) )
    {
        if ( --time_out_count == 0 )
            return -1;
    }
    *byte = (temp_byte >> PLIP_NIB_SHFTR) & 0x0f;
    outp(PARPORT_DATA, PLIP_NIB_STROBE);


    /* Wait for line /BUSY=0 (Status.7=1) and transmit high nibble
     */
    time_out_count = TIME_OUT_COUNT;
    while ( ((temp_byte = inp(PARPORT_STAT)) & PLIP_NIB_ACK) == 0 )
    {
        if ( --time_out_count == 0 )
            return -1;
    }
    *byte |= (temp_byte << PLIP_NIB_SHFTL) & 0xf0;
    outp(PARPORT_DATA, 0);

    return 0;
}

/* -----------------------------------------
 * parport_isr()
 *
 * Parallel port interface interrupt handler
 * will be triggered by a start transmissing bit.
 *
 * ----------------------------------------- */
static void __interrupt __far parport_isr(void)
{
    int         i;
    uint16_t    temp_wr_ptr;
    uint16_t    packet_len;
    uint8_t     pack_len_high;
    uint8_t     pack_len_low;
    uint8_t     byte;
    uint8_t     check_sum = 0;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    //_enable();  // enable interrupts during PLIP processing

    /* Store the incoming packet only if there is room in the buffer.
     * if not, drop the packet until the buffer is cleared.
     * Move the 'recv_wr_ptr' only if a full packet was accepted and
     * stored in the 'recv_buffer'.
     * This interrupt routine does not need to be fast as PLIP data
     * transfer occurs with all interrupts enabled except for the
     * printer port IRQ which triggers this interrupt.
     * 
     * 'recv_buffer' structure will include 2-byte packet length,
     * followed by the packet data. 'recv_rd_ptr' will point to the
     * packet length bytes of the next available packet to read,
     * and the 'recv_wr_ptr' will point to the next free byte location
     * in the buffer. 'plip_packet_cnt' will indicate if there are
     * any unread packets in the buffer.
     * 
     */

    /* PLIP receiver processing:
     *  1. Disable ineterrputs on Ack line (Ctrl.4=0)
     *  2. Acknowledge with header nibble '0x08' (Data.3=1)
     *  3. Read count-low byte
     *  4. Read count-high byte
     *  5. ... data bytes
     *     ... calculate running checksum (with count bytes?)
     *  6. Read checksum byte
     *  7. Compare check sum byte
     *  8. Reenable interrupt on Ack line (Ctrl.4=1)
     *  9. Send EOI to PIC
     * 
     */

    /* Disable Ack line interrupts and acknowledge the
     * transmission request to the initiator
     */
    outp(PARPORT_CTRL, 0);

    outp(PARPORT_DATA, PLIP_TX_ACK);

    /* Establish a temporary buffer pointer and get packet length
     */
    temp_wr_ptr = recv_wr_ptr;

    if ( receive_byte(&pack_len_low) != 0 )
    {
        goto ABORT_PLIP_IN;
    }

    if ( receive_byte(&pack_len_high) != 0 )
    {
        goto ABORT_PLIP_IN;
    }

    packet_len = (((uint16_t)pack_len_high) << 8) + pack_len_low;

    /* Check if we have enough space in the buffer
     */
    if ( (packet_len + 2) > free_cap )
    {
        goto ABORT_PLIP_IN;
    }

    /* Store packet length then packet data in the buffer
     */
    recv_buffer[temp_wr_ptr++] = pack_len_low;
    if ( temp_wr_ptr == BYTE_IN )
        temp_wr_ptr = 0;

    recv_buffer[temp_wr_ptr++] = pack_len_high;
    if ( temp_wr_ptr == BYTE_IN )
        temp_wr_ptr = 0;

    for ( i = 0; i < packet_len; i++ )
    {
        if ( receive_byte(&byte) != 0 )
        {
            goto ABORT_PLIP_IN;
        }
        recv_buffer[temp_wr_ptr++] = byte;
        if ( temp_wr_ptr == BYTE_IN )
            temp_wr_ptr = 0;
        check_sum += byte;
    }

    /* Read checksum and check against calculated sum
     */
    if ( receive_byte(&byte) != 0 ||
         check_sum != byte             )
    {
#ifdef DRV_DEBUG_FUNC_PARAM
        printf("  receive checksum error.\n");
#endif
        goto ABORT_PLIP_IN;
    }

    /* We have a good packet
     */
    recv_wr_ptr = temp_wr_ptr;
    plip_packet_cnt++;
    free_cap -= (packet_len + 2);

    /* Reenable interrupts and signal 
     * end of interrupt for 8259 controller
     */
ABORT_PLIP_IN:

#ifdef DRV_DEBUG_FUNC_EXIT
    printf("  receive error.\n");
#endif

    outp(PARPORT_DATA, 0);
    outp(PARPORT_CTRL, PARP_CTRL_INT);
    outp(ISR, EOI);
}

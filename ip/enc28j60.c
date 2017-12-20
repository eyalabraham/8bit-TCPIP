/* ***************************************************************************

  enc28j60.c

   This is an Ethernet Interface driver for Microchip ENC28J60.
   It follows the LwIP skeleton driver structure, and implements
   driver support for my setup

   Eyal Abraham, March 2017

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

#include    "ppispi.h"

#include    "ip/options.h"
#include    "ip/stack.h"
#include    "ip/enc28j60.h"
#include    "ip/enc28j60-hw.h"

/* -----------------------------------------
   static function prototype
----------------------------------------- */

// ENC28J60 device register access functions through SPI
static spiDevErr_t  setRegisterBank(regBank_t);
static spiDevErr_t  readControlRegister(ctrlReg_t, uint8_t*);
static spiDevErr_t  writeControlRegister(ctrlReg_t, uint8_t);
static spiDevErr_t  readPhyRegister(phyReg_t, uint16_t*);
static spiDevErr_t  writePhyRegister(phyReg_t, uint16_t);
static int          controlBit(ctrlReg_t, uint8_t);
static spiDevErr_t  setControlBit(ctrlReg_t, uint8_t);
static spiDevErr_t  clearControlBit(ctrlReg_t, uint8_t);
#if DRV_DMA_IO
static void         spiCallBack(void);
#endif
static spiDevErr_t  readMemBuffer(uint8_t*, uint16_t, uint16_t);
static spiDevErr_t  writeMemBuffer(uint8_t*, uint16_t, uint16_t);

static void         ethReset(void);
static int          packetWaiting(void);
static void         extractPacketInfo(struct enc28j60_t*);

/* -----------------------------------------
   driver globals
----------------------------------------- */
volatile int16_t    dmaComplete = 0;                    // DMA block IO completion flag
struct enc28j60_t   deviceState;                        // this interface private data structure

/* -----------------------------------------
 * setRegisterBank()
 *
 *  set/select an enc28j60 register bank through ECON1 register
 *
 *  return 0 if no error, otherwise return SPI error level
 *
 *  decided to ignore spiWrite error, and only report
 *  spiRead errors, mainly time-out
 *
 * ----------------------------------------- */
static spiDevErr_t setRegisterBank(regBank_t bank)
{
    uint8_t     econ1Reg;
    spiDevErr_t result = SPI_BUSY;

    if ( bank == BANK0 || bank == BANK1 || bank == BANK2 || bank == BANK3 )
    {
        spiWriteByteKeepCS(ETHERNET_WR, (OP_RCR | ECON1));  // read ECON1
        if ( (result = spiReadByte(ETHERNET_RD, &econ1Reg)) != SPI_OK )
            goto ABORT_BANKSEL;
        econ1Reg &= 0xfc;                                   // set bank number bits [BSEL1 BSEL0]
        econ1Reg |= (((uint8_t)bank) >> 5);
        spiWriteByteKeepCS(ETHERNET_WR, (OP_WCR | ECON1));  // write ECON1
        spiWriteByte(ETHERNET_WR, econ1Reg);
    }

ABORT_BANKSEL:
#ifdef DRV_DEBUG_FUNC_EXIT
    printf("exit: %s(%d) %d\n", __func__, bank, result);
#endif
    return result;                                          // bad bank number parameter passed in
}

/* -----------------------------------------
 * readControlRegister()
 *
 *  read an enc28j60 control register
 *  read any of the ETH, MAC and MII registers in any order
 *  the function will take care of switching register banks and
 *  of ETH vs. MAC/MII register reads that require an extra dummy byte read
 *
 *  return 0 if no error, otherwise return SPI error level
 *
 *  decided to ignore spiWrite error, and only report
 *  spiRead errors, mainly time-out
 *
 * ----------------------------------------- */
static spiDevErr_t readControlRegister(ctrlReg_t reg, uint8_t* byte)
{
    uint8_t     bank;
    uint8_t     regId;
    uint8_t     regValue;
    spiDevErr_t result = SPI_RD_ERR;

    bank = (reg & 0x60);                                // isolate bank number
    regId = (reg & 0x1f);                               // isolate register number

    if ( (result = setRegisterBank(bank)) != SPI_OK)    // select bank
        goto ABORT_RCR;

    spiWriteByteKeepCS(ETHERNET_WR, (OP_RCR | regId));  // issue a control register read command

    if ( reg & MACMII )                                 // is this a MAC or MII register?
    {                                                   // yes, then issue an extra dummy read
        if ( (result = spiReadByteKeepCS(ETHERNET_RD, &regValue)) != SPI_OK)
            goto ABORT_RCR;
    }

    if ( (result = spiReadByte(ETHERNET_RD, &regValue)) != SPI_OK) //issue actual read for the byte
        goto ABORT_RCR;

    *byte = regValue;

ABORT_RCR:
#ifdef DRV_DEBUG_FUNC_EXIT
    printf("exit: %s(0x%02x,0x%02x) %d\n", __func__, reg, *byte, result);
#endif
    return result;
}

/* -----------------------------------------
 * writeControlRegister()
 *
 *  write to an enc28j60 control register
 *
 *  return 0 if no error, otherwise return SPI error level
 *
 *  decided to ignore spiWrite error, and only report
 *  spiRead errors, mainly time-out
 *
 * ----------------------------------------- */
static spiDevErr_t writeControlRegister(ctrlReg_t reg, uint8_t byte)
{
    uint8_t     bank;
    uint8_t     regId;
    spiDevErr_t result = SPI_WR_ERR;

    bank = (reg & 0x60);                                // isolate bank number
    regId = (reg & 0x1f);                               // isolate register number

    if ( (result = setRegisterBank(bank)) != SPI_OK)    // select bank
        goto ABORT_WCR;

    spiWriteByteKeepCS(ETHERNET_WR, (OP_WCR | regId));  // issue a control register write command
    spiWriteByte(ETHERNET_WR, byte);                    // and send the data byte

ABORT_WCR:
#ifdef DRV_DEBUG_FUNC_EXIT
    printf("exit: %s(0x%02x,0x%02x) %d\n", __func__, reg, byte, result);
#endif
    return result;
}

/* -----------------------------------------
 * readPhyRegister()
 *
 *  read from an enc28j60 PHY register:
 *  1. Write the address of the PHY register to read
 *     from into the MIREGADR register.
 *  2. Set the MICMD.MIIRD bit. The read operation
 *     begins and the MISTAT.BUSY bit is set.
 *  3. Wait 10.24 μs. Poll the MISTAT.BUSY bit to be
 *     certain that the operation is complete. While
 *     busy, the host controller should not start any
 *     MIISCAN operations or write to the MIWRH
 *     register.
 *     When the MAC has obtained the register
 *     contents, the BUSY bit will clear itself.
 *  4. Clear the MICMD.MIIRD bit.
 *  5. Read the desired data from the MIRDL and
 *     MIRDH registers. The order that these bytes are
 *     accessed is unimportant.
 *
 *  return 0 if no error, otherwise return SPI error level
 *
 *  decided to ignore spiWrite error, and only report
 *  spiRead errors, mainly time-out
 *
 * ----------------------------------------- */
static spiDevErr_t readPhyRegister(phyReg_t reg, uint16_t* word)
{
    uint8_t     byte;
    spiDevErr_t result = SPI_RD_ERR;

    if ( (result = writeControlRegister(MIREGADR, reg)) != SPI_OK)  // set PHY register address
        goto ABORT_PHYRD;

    setControlBit(MICMD, MICMD_MIIRD);              // start the read operation
    while ( controlBit(MISTAT, MISTAT_BUSY) ) {};   // wait for read operation to complete TODO timeouts?
    clearControlBit(MICMD, MICMD_MIIRD);            // clear read request
    readControlRegister(MIRDL, &byte);              // read low byte
    *word = byte;
    readControlRegister(MIRDH, &byte);              // read high byte
    *word += ((uint16_t) byte) << 8;

ABORT_PHYRD:
#ifdef DRV_DEBUG_FUNC_EXIT
    printf("exit: %s(0x%02x,0x%04x) %d\n", __func__, reg, *word, result);
#endif
    return result;
}

/* -----------------------------------------
 * writePhyRegister()
 *
 *  write to an enc28j60 PHY register
 *  1. Write the address of the PHY register to write to
 *     into the MIREGADR register.
 *  2. Write the lower 8 bits of data to write into the
 *     MIWRL register.
 *  3. Write the upper 8 bits of data to write into the
 *     MIWRH register. Writing to this register automatically
 *     begins the MII transaction, so it must
 *     be written to after MIWRL. The MISTAT.BUSY
 *     bit becomes set.
 *
 *  return SPI_OK if no error, otherwise return SPI error level
 *
 *  decided to ignore spiWrite error, and only report
 *  spiRead errors, mainly time-out
 *
 * ----------------------------------------- */
static spiDevErr_t writePhyRegister(phyReg_t reg, uint16_t word)
{
    spiDevErr_t result = SPI_WR_ERR;

    if ( (result = writeControlRegister(MIREGADR, reg)) != SPI_OK)  // set PHY register address
        goto ABORT_PHYWR;

    writeControlRegister(MIRDL, (uint8_t) word);
    writeControlRegister(MIRDH, (uint8_t) (word >> 8));
    while ( controlBit(MISTAT, MISTAT_BUSY) ) {};   // wait for write operation to complete TODO timeouts?

ABORT_PHYWR:
#ifdef DRV_DEBUG_FUNC_EXIT
    printf("exit: %s(0x%02x,0x%04x) %d\n", __func__, reg, word, result);
#endif
    return result;
}

/* -----------------------------------------
 * controlBit()
 *
 *  read and test control register bit(s)
 *  the control register value is tested using a
 *  bitwise AND with 'position'.
 *
 * ----------------------------------------- */
static int controlBit(ctrlReg_t reg, uint8_t position)
{
    uint8_t     value;
    spiDevErr_t result = 0;

    if ( readControlRegister(reg, &value) == SPI_OK)    // get register value
        result = ((value & position) ? 1 : 0);

#ifdef DRV_DEBUG_FUNC_EXIT
    printf("exit: %s(0x%02x,0x%02x) %d\n", __func__, reg, position, result);
#endif
    return result;
}

/* -----------------------------------------
 * setControlBit()
 *
 *  set a control register bit position
 *  -- register OR 'position'
 *
 * ----------------------------------------- */
static spiDevErr_t setControlBit(ctrlReg_t reg, uint8_t position)
{
    uint8_t     bank;
    uint8_t     regId;
    uint8_t     regValue;
    spiDevErr_t result = -1;                                // which is also 'SPI_BUSY'...

    if ( reg & MACMII )                                     // is this a MAC or MII register?
    {                                                       // yes, can't use BFS command on MAC or MII, but...
        result = readControlRegister(reg, &regValue);       // can read register,
        regValue |= position;                               // modify
        result = writeControlRegister(reg, regValue);       // and write back
    }
    else
    {
        bank = (reg & 0x60);                                // isolate bank number
        regId = (reg & 0x1f);                               // isolate register number

        if ( (result = setRegisterBank(bank)) != SPI_OK)    // select bank
            goto ABORT_BFS;

        spiWriteByteKeepCS(ETHERNET_WR, (OP_BFS | regId));  // issue a control register write command
        spiWriteByte(ETHERNET_WR, position);                // and send the data byte
    }

ABORT_BFS:
#ifdef DRV_DEBUG_FUNC_EXIT
    printf("exit: %s(0x%02x,0x%02x) %d\n", __func__, reg, position, result);
#endif
    return result;
}

/* -----------------------------------------
 * clearControlBit()
 *
 *  clear a control register bit position
 *  -- register AND (NOT 'position')
 *
 * ----------------------------------------- */
static spiDevErr_t clearControlBit(ctrlReg_t reg, uint8_t position)
{
    uint8_t     bank;
    uint8_t     regId;
    uint8_t     regValue;
    spiDevErr_t result = -1;                                // which is also 'SPI_BUSY'...

    if ( reg & MACMII )                                     // is this a MAC or MII register?
    {                                                       // yes, can't use BFC command on MAC or MII, but...
        result = readControlRegister(reg, &regValue);       // can read register,
        regValue &= ~position;                              // modify
        result = writeControlRegister(reg, regValue);       // and write back
    }
    else
    {
        bank = (reg & 0x60);                                // isolate bank number
        regId = (reg & 0x1f);                               // isolate register number

        if ( (result = setRegisterBank(bank)) != SPI_OK)    // select bank
            goto ABORT_BFC;

        spiWriteByteKeepCS(ETHERNET_WR, (OP_BFC | regId));  // issue a control register write command
        spiWriteByte(ETHERNET_WR, position);                // and send the data byte
    }

ABORT_BFC:
#ifdef DRV_DEBUG_FUNC_EXIT
    printf("exit: %s(0x%02x,0x%02x) %d\n", __func__, reg, position, result);
#endif
    return result;
}

/*------------------------------------------------
 * spiCallBack()
 *
 *  SPI block transfer DMA completion callback
 *
 */
#if DRV_DMA_IO
static void spiCallBack(void)
{
    dmaComplete = 1;

#ifdef DRV_DEBUG_FUNC_PARAM
    printf("exit: %s() dmaComplete=%d\n", __func__, dmaComplete);
#endif
}
#endif /* DRV_DMA_IO */

/* -----------------------------------------
 * readMemBuffer()
 *
 *  read 'length' bytes from ENC28J60 memory
 *  starting at 'address' into destination location 'dest'
 *  use DMA or single byte access.
 *  always assume internal read pointer ERDPT is auto increment
 *  function does not range check 'address' parameter
 *  return 0 if no error, otherwise return SPI error level
 *
 * ----------------------------------------- */
static spiDevErr_t readMemBuffer(uint8_t *dest, uint16_t address, uint16_t length)
{
    spiDevErr_t result = SPI_RD_ERR;
    int         i;

#ifdef DRV_DEBUG_FUNC_PARAM
    printf("enter: %s()\n  len=%u address=0x%04x\n", __func__, length, address);
#endif

    if ( length == 0 )
        return SPI_RD_ERR;

    if ( address != USE_CURR_ADD )                  // change address pointer or use default
    {
        writeControlRegister(ERDPTL, LOW_BYTE(address));
        writeControlRegister(ERDPTH, HIGH_BYTE(address));
    }

    if ( length == 1 )
    {                                               // read a single byte
        spiWriteByteKeepCS(ETHERNET_WR, OP_RBM);    // issue read memory command
        result = spiReadByte(ETHERNET_RD, dest);    // read a byte and release CS
    }
    else
    {                                               // read data from device memory
        spiWriteByteKeepCS(ETHERNET_WR, OP_RBM);    // issue read memory command
#if DRV_DMA_IO
        dmaComplete = 0;
        result = spiReadBlock(ETHERNET_RD, dest, length, spiCallBack); // start DMA transfer
        if ( result == SPI_OK )
            while ( !dmaComplete ) {};              // wait for DMA transfer to complete
#else
        for ( i = 0; i < (length-1); i++)
            spiReadByteKeepCS(ETHERNET_RD, (dest+i));
        result = spiReadByte(ETHERNET_RD, (dest+i));
#endif /* DRV_DMA_IO */
    }

    return result;
}

/* -----------------------------------------
 * writeMemBuffer()
 *
 *  write 'length' bytes into ENC28J60 memory
 *  starting at 'address' from source location 'src'
 *  use DMA or single byte access.
 *  always assume internal read pointer EWRPT is auto increment
 *  function does not range check 'address' parameter
 *  return 0 if no error, otherwise return SPI error level
 *
 * ----------------------------------------- */
static spiDevErr_t writeMemBuffer(uint8_t *src, uint16_t address, uint16_t length)
{
    spiDevErr_t result = SPI_WR_ERR;
    int         i;

#ifdef DRV_DEBUG_FUNC_PARAM
    printf("enter: %s()\n  len=%u address=0x%04x\n", __func__, length, address);
#endif

    if ( length == 0 )
        return SPI_WR_ERR;

    if ( address != USE_CURR_ADD )                      // change address pointer or use default
    {
        writeControlRegister(EWRPTL, LOW_BYTE(address));
        writeControlRegister(EWRPTH, HIGH_BYTE(address));
    }

    if ( length == 1 )
    {                                                   // write a single byte
        spiWriteByteKeepCS(ETHERNET_WR, OP_WBM);        // issue write memory command
        result = spiWriteByte(ETHERNET_WR, *src);       // write a byte and release CS
    }
    else
    {                                                   // write data block to device memory
        spiWriteByteKeepCS(ETHERNET_WR, OP_WBM);        // issue write memory command
#if DRV_DMA_IO
        dmaComplete = 0;
        result = spiWriteBlock(ETHERNET_WR, src, length, spiCallBack); // start DMA transfer
        if ( result == SPI_OK )
            while ( !dmaComplete ) {};                  // wait for DMA transfer to complete
#else
        for ( i = 0; i < (length-1); i++)               // write everything except for the last byte
            spiWriteByteKeepCS(ETHERNET_WR, *(src+i));
        result = spiWriteByte(ETHERNET_WR, *(src+i));   // write the last byte and un-assert CS
#endif /* DRV_DMA_IO */
    }

    return result;
}

/* -----------------------------------------
 * ethReset()
 *
 *  software reset of the ENC28J60
 *  after issuing this reset, 50uSec need to elapse before
 *  proceeding to altering or reading PHY registers
 *
 * ----------------------------------------- */
static void ethReset(void)
{
    int     i;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    spiWriteByte(ETHERNET_WR, OP_SC);           // issue a reset command
    for (i = 0; i < 1100; i++);                 // wait ~4mSec because ESTAT.CLKRDY is not reliable (errata #2, DS80349C)
}

/* -----------------------------------------
 * packetWaiting()
 *
 *  return '1' if unread packet(s) waiting in Rx buffer
 *  return '0' if not
 *
 * ----------------------------------------- */
static int packetWaiting(void)
{
    uint8_t    packetCount;

    readControlRegister(EPKTCNT, &packetCount); // check packet count waiting in input buffer (errata #6, DS80349C)
    return ( packetCount > 0 ? 1 : 0);
}

/* -----------------------------------------
 * extractPacketInfo()
 *
 *  we've determined that a packet is waiting in the
 *  receiver buffer, this function extracts the packet
 *  status vector into the device/interface private structure,
 *  advances the read pointer, but does not read the packet
 *  data.
 *  the function assumes that the ERDPTH:L pointer is set
 *  to the start of the packet vector, after reading the vector
 *  the ERDPTH:L pointer point to the start of the packet to read
 *
 * ----------------------------------------- */
static void extractPacketInfo(struct enc28j60_t *ethif)
{
    uint8_t    i;
    uint8_t    temp;

    spiWriteByteKeepCS(ETHERNET_WR, OP_RBM);            // initiate memory read

    for ( i = 0; i < (sizeof(struct rxStat_t)-1); i++ ) // loop to read first bytes of status vector
    {
        spiReadByteKeepCS(ETHERNET_RD, &temp);
        ethif->rxStatusVector[i] = temp;
    }

    spiReadByte(ETHERNET_RD, &temp);                    // read last byte of vector and release CS
    ethif->rxStatusVector[i] = temp;
}

/* -----------------------------------------
 * link_output()
 *
 * This function does the actual transmission of the packet.
 * The packet is contained in the pbuf that is passed to the function.
 *
 * param:  'netif' the interface structure for this ethernet interface
 *         p the packet pbuf to send (e.g. IP packet including MAC addresses and type)
 * return: ERR_OK if the packet could be sent
 *         an ip4_err_t value if the packet couldn't be sent
 *
 * ----------------------------------------- */
ip4_err_t link_output(struct net_interface_t* const netif, struct pbuf_t *p)
{
    uint8_t             tempU8;
    uint16_t            tempU16;
    struct enc28j60_t  *ethif;
    ip4_err_t           result = ERR_OK;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    ethif = (struct enc28j60_t*)netif->state;
    
    writeControlRegister(ETXSTL, LOW_BYTE(INIT_ETXST));         // explicitly set the transmit buffer start
    writeControlRegister(ETXSTH, HIGH_BYTE(INIT_ETXST));

    // transfer packet data into ENC28J60 output buffer
    // the size of the data in each pbuf is kept in the ->len variable.
    assert(writeMemBuffer(p->pbuf, (uint16_t) INIT_EWRPT, p->len) == SPI_OK); // TODO convert to proper error handling, with: do { ... } while (0);

    tempU16 = (uint16_t) INIT_ETXST;                            // calculate buffer end address
    tempU16 += p->len;

    writeControlRegister(ETXNDL, LOW_BYTE(tempU16));            // set buffer end address
    writeControlRegister(ETXNDH, HIGH_BYTE(tempU16));

#ifdef DRV_DEBUG_FUNC_PARAM
    printf("  len=%u txBufferEnd=0x%04x\n", p->len, tempU16);
#endif

#if !FULL_DUPLEX
    setControlBit(ECON1, ECON1_TXRST);                          // implementing per errata #12 (document DS80349C)
    clearControlBit(ECON1, ECON1_TXRST);
    clearControlBit(EIR, EIR_TXERIF);
#endif

    clearControlBit(EIR, EIR_TXIF);                             // clear transmit interrupt flag
    setControlBit(ECON1, ECON1_TXRTS);                          // enable/start frame transmission

    while ( controlBit(EIR, EIR_TXIF) == 0 &&                   // per errata #13 (document DS80349C)
            controlBit(EIR, EIR_TXERIF) == 0 ) {}               // wait for transmission to complete or to error out

    clearControlBit(ECON1, ECON1_TXRTS);

    tempU16++;                                                  // read the packet transmit status vector
    readMemBuffer(ethif->txStatusVector, tempU16, sizeof(struct txStat_t));

#ifdef DRV_DEBUG_FUNC_PARAM
    printf("  bytes Tx %u\n  Stat1    0x%02x\n  Stat2    0x%02x\n  Stat3    0x%02x\n  total Tx %u\n",
            ethif->txStatVector.txByteCount,
            ethif->txStatVector.txStatus1,
            ethif->txStatVector.txStatus2,
            ethif->txStatVector.txStatus3,
            ethif->txStatVector.txTotalXmtCount);
#endif

    if ( controlBit(EIR, EIR_TXERIF) ||
         controlBit(ESTAT, ESTAT_TXABRT) )                      // check for errors
    {
        if ( ethif->txStatVector.txStatus2 & LATE_COLL_STAT )   // determine type of transmit link collisions
            result = ERR_TX_LCOLL;                              // per errata #15
        else
            result = ERR_TX_COLL;

#ifdef DRV_DEBUG_FUNC_PARAM
        printf("  *** packet transmission failure ***\n");
#endif
    }

  return result;
}

/* -----------------------------------------
 * link_input()
 *
 * allocate a pbuf and transfer the bytes of the incoming
 * packet from the interface into the pbuf.
 *
 * param:  'netif' pointer to the interface to be read
 * return: a pbuf filled with the received packet (including MAC header)
 *         NULL on memory error
 * ----------------------------------------- */
struct pbuf_t* const link_input(struct net_interface_t* const netif)
{
    struct pbuf_t      *p;
    uint16_t            len;
    struct enc28j60_t  *ethif;
    uint8_t             rdPtrL, rdPtrH;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    if ( !packetWaiting() )
        return NULL;

    ethif = (struct enc28j60_t*)netif->state;
    
    // update ERDPT to point to next packet read address start
    writeControlRegister(ERDPTL, ethif->rxStatVector.nextPacketL);
    writeControlRegister(ERDPTH, ethif->rxStatVector.nextPacketH);

    // then read received packet information
    // extract next packet address, current packet length and errors bit[20,21,22,23]
    // into 'ethif'
    extractPacketInfo(ethif);

#ifdef DRV_DEBUG_FUNC_PARAM
    printf("  len   %u\n next  0x%02x%02x\n stat1 0x%02x\n stat2 0x%02x\n",
               ethif->rxStatVector.rxByteCount,
               ethif->rxStatVector.nextPacketH,
               ethif->rxStatVector.nextPacketL,
               ethif->rxStatVector.rxStatus1,
               ethif->rxStatVector.rxStatus2);
#endif

    // Obtain the size of the packet and put it into the "len" variable.
    len = ethif->rxStatVector.rxByteCount;
    assert(len <= PACKET_BUF_SIZE);

    // allocate a pbuf from the pool
    p = pbuf_allocate();

    if (p != NULL)
    {
        // read the waiting ethernet packet into the buffer
        readMemBuffer(p->pbuf, USE_CURR_ADD, len);
        // set buffer length and adjust to ignore CRC bytes
        p->len = len - 4;

#ifdef DRV_DEBUG_FUNC_PARAM
        {
            int i;
            printf("  dst: ");
            for (i = 0; i < 6; i++)
                printf("%02x ", (p->pbuf)[i]);
            printf("\n  src: ");
            for (i = 6; i < 12; i++)
                printf("%02x ", (p->pbuf)[i]);
            printf("\n  typ: ");
            for (i = 12; i < 14; i++)
                printf("%02x ", (p->pbuf)[i]);
            printf("\n");
        }
#endif

    }
#ifdef DRV_DEBUG_FUNC_PARAM
    else
    {
        printf("  *** 'pbuf' alloc err, packet dropped ***\n");
    }
#endif

    /* acknowledge that a packet has been read from ENC28J60
     * by updating ERXRDPT. Also implementing errata #14 as:
     *
     * if (Next Packet Pointer = ERXST)
     * then:
     *      ERXRDPT = ERXND
     *      ERXND should always be on odd address
     * else:
     *      ERXRDPT = 'Next Packet Pointer' – 1
     *      'Next Packet Pointer' is always on even address
     */
    if ( ethif->rxStatVector.nextPacketL == LOW_BYTE(INIT_ERXST) &&
         ethif->rxStatVector.nextPacketH == HIGH_BYTE(INIT_ERXST) )
    {
        rdPtrL = LOW_BYTE(INIT_ERXND);
        rdPtrH = HIGH_BYTE(INIT_ERXND);
    }
    else
    {
        rdPtrL = ethif->rxStatVector.nextPacketL - 1;
        rdPtrH = ethif->rxStatVector.nextPacketH;
        if ( rdPtrL == 0xff )
            rdPtrH--;
    }
    writeControlRegister(ERXRDPTL, rdPtrL);
    writeControlRegister(ERXRDPTH, rdPtrH);
    setControlBit(ECON2, ECON2_PKTDEC);                               // decrement packet waiting count

    return p;
}

/* -----------------------------------------
 * link_state()
 *
 *  returns the link status
 *  by reading LLSTAT in PHSTAT1
 *  ( TODO what is the effect of using LSTAT in PHSTAT2? )
 *
 * ----------------------------------------- */
int link_state(void)
{
    uint16_t    phyStatus;
    int         linkState;

    readPhyRegister(PHSTAT2, &phyStatus);
    linkState = ((phyStatus & PHSTAT2_LSTAT) ? 1 : 0);
/*
    readPhyRegister(PHSTAT1, &phyStatus);
    linkState = ((phyStatus & PHSTAT1_LLSTAT) ? 1 : 0);
*/
#ifdef DRV_DEBUG_FUNC_EXIT
    printf("exit: %s(%d)\n", __func__, linkState);
#endif

    return linkState;
}

/* -----------------------------------------
 * enc28j60Init()
 *
 * hardware initialization function for the ENC28J60 chip called from interface_init().
 *
 * param:  pointer to interface private data/state structure
 * return: ETH_OK initialization done and link up,
 *         other values if initialization failed
 *
 * ----------------------------------------- */
struct enc28j60_t* enc28j60Init(void)
{
    struct enc28j60_t *result = NULL;
    uint16_t           tmpPhyReg;
    uint8_t            perPacketCtrl = PER_PACK_CTRL;

#ifdef DRV_DEBUG_FUNC_NAME
    printf("enter: %s()\n",__func__);
#endif

    ethReset();                                             // issue a reset command

    clearControlBit(ECON1, ECON1_TXRTS);                    // disable frame transmission
    clearControlBit(ECON1, ECON1_RXEN);                     // disable reception

    memset(&deviceState, 0, sizeof(struct enc28j60_t));     // zero out data structure before populating it

    readPhyRegister(PHID1, &(deviceState.phyID1));          // read and store PHY ID and device revision
    readPhyRegister(PHID2, &(deviceState.phyID2));
    readControlRegister(EREVID, &(deviceState.revID));

#ifdef DRV_DEBUG_FUNC_PARAM
    printf("  PHID1=0x%04x PHID2=0x%04x Rev=0x%02x\n", deviceState.phyID1, deviceState.phyID2, deviceState.revID);
#endif

    assert(deviceState.phyID1 == PHY_ID1);                  // assert on ID values!
    assert(deviceState.phyID2 == PHY_ID2);

    /* initialize device buffer pointers and receiver filter
     */
    writeControlRegister(ERXSTL, LOW_BYTE(INIT_ERXST));     // initialize receive buffer start
    writeControlRegister(ERXSTH, HIGH_BYTE(INIT_ERXST));
    writeControlRegister(ERXNDL, LOW_BYTE(INIT_ERXND));     // initialize receive buffer end
    writeControlRegister(ERXNDH, HIGH_BYTE(INIT_ERXND));
    writeControlRegister(ERDPTL, LOW_BYTE(INIT_ERDPT));     // initialize read pointer
    writeControlRegister(ERDPTH, HIGH_BYTE(INIT_ERDPT));
    writeControlRegister(ERXWRPTL, LOW_BYTE(INIT_ERXWRPT)); // force write pointer to ERXST, Errata #5 workaround
    writeControlRegister(ERXWRPTH, HIGH_BYTE(INIT_ERXWRPT));
    writeControlRegister(ERXRDPTL, LOW_BYTE(INIT_ERXRDPT)); // force read pointer to ERXST
    writeControlRegister(ERXRDPTH, HIGH_BYTE(INIT_ERXRDPT));

    writeControlRegister(ERXFCON, INIT_ERXFCON);            // setup device packet filter

    /* MAC initialization settings
     */
    setControlBit(MACON1, MACON1_MARXEN);                                       // enable the MAC to receive frames
#if FULL_DUPLEX
    setControlBit(MACON1, (MACON1_TXPAUS | MACON1_RXPAUS));                     // for full duplex, set TXPAUS and RXPAUS to allow flow control
    setControlBit(MACON3, MACON3_FULDPX);                                       // set for full duplex
#else
    clearControlBit(MACON1, (MACON1_TXPAUS | MACON1_RXPAUS));                   // for half duplex, clear TXPAUS and RXPAUS
    clearControlBit(MACON3, MACON3_FULDPX);                                     // clear for half duplex
    setControlBit(MACON4, MACON4_DEFER);                                        // wait indefinitely for medium to become free
    writeControlRegister(MACLCON1, INIT_MACLCON1);                              // retransmission maximum
    writeControlRegister(MACLCON2, INIT_MACLCON2);                              // collision window
#endif
    setControlBit(MACON3, (MACON3_PADCFG | MACON3_TXCRCEN | MACON3_FRMLEN));    // full frame padding + CRC

    writeControlRegister(MAMXFLL, LOW_BYTE(INIT_MAMXFL));   // max frame size
    writeControlRegister(MAMXFLH, HIGH_BYTE(INIT_MAMXFL));

    writeControlRegister(MABBIPG, INIT_MABBIPG);            // no detail why, just how to program them
    writeControlRegister(MAIPGL, INIT_MAIPGL);
    writeControlRegister(MAIPGH, INIT_MAIPGH);

    writeControlRegister(MAADR1, MAC0);                     // MAC address
    writeControlRegister(MAADR2, MAC1);
    writeControlRegister(MAADR3, MAC2);
    writeControlRegister(MAADR4, MAC3);
    writeControlRegister(MAADR5, MAC4);
    writeControlRegister(MAADR6, MAC5);

    writePhyRegister(PHLCON, INIT_PHLCON);                  // LED control

#if FULL_DUPLEX
    readPhyRegister(PHCON1, &tmpPhyReg);                    // set PHY to match half duplex setup MACON3_FULDPX
    tmpPhyReg |= PHCON1_PDPXMD;
    tmpPhyReg &= ~PHCON1_PLOOPBK;                           // make sure loop-back is off
    writePhyRegister(PHCON1, tmpPhyReg);
#else
    readPhyRegister(PHCON1, &tmpPhyReg);                    // set PHY to match half duplex setup MACON3_FULDPX
    tmpPhyReg &= ~PHCON1_PDPXMD;
    tmpPhyReg &= ~PHCON1_PLOOPBK;                           // make sure loop-back is off
    writePhyRegister(PHCON1, tmpPhyReg);

    readPhyRegister(PHCON2, &tmpPhyReg);                    // disable half duplex loopback
    tmpPhyReg |= PHCON2_HDLDIS;
    writePhyRegister(PHCON2, tmpPhyReg);
#endif  /* FULL_DUPLEX */

    writeMemBuffer(&perPacketCtrl, (uint16_t) INIT_ETXST, 1);  // prep Tx buffer with per-packet control byte

    setControlBit(ECON2, ECON2_AUTOINC);                    // set auto increment memory pointer operation

    tmpPhyReg = 30000;
    while ( tmpPhyReg && link_state() == 0 )                 // wait for link up
    {
        tmpPhyReg--;
    }

    if ( link_state() == 1 )
    {
        setControlBit(ECON1, ECON1_RXEN);                   // enable frame reception TODO do I do these here?
        result = &deviceState;
    }

#ifdef DRV_DEBUG_FUNC_EXIT
    printf("  PHY ID 0x%04x:0x%04x\n", deviceState.phyID1, deviceState.phyID2);
    printf("exit: %s() %d\n", __func__, result);
#endif

    return result;
}

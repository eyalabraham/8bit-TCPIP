/* ***************************************************************************

  slip.h

  header file for a SLIP interface driver

  November 2017 - Created

*************************************************************************** */

#ifndef __SLIP_H__
#define __SLIP_H__

#include    "ip/error.h"
#include    "ip/types.h"

/* -----------------------------------------
   SLIP interface data structure
----------------------------------------- */
struct slip_t
{
    uint16_t    nextPacket;
    uint16_t    currentLength;
};

/* -----------------------------------------
   interface functions
----------------------------------------- */
struct slip_t*       slip_init(void);
ip4_err_t            slip_output(struct net_interface_t* const, struct pbuf_t* const);
struct pbuf_t* const slip_input(struct net_interface_t* const);
int                  slip_link_state(void);

#endif  /* __SLIP_H__ */

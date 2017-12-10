/* ***************************************************************************

  enc28j60.h

  header file for Microchip EMC28J60 ethernet chip driver

  March 2017 - Created

*************************************************************************** */

#ifndef __ENC28J60_H__
#define __ENC28J60_H__

#include    "ip/error.h"
#include    "ip/enc28j60-hw.h"
#include    "types.h"

/* -----------------------------------------
   interface functions
----------------------------------------- */
struct enc28j60_t*   enc28j60Init(void);
ip4_err_t            link_output(struct net_interface_t* const, struct pbuf_t*);
struct pbuf_t* const link_input(struct net_interface_t* const);
int                  link_state(void);                      // test link condition

#endif  /* __ENC28J60_H__ */

/* ***************************************************************************

  plip.h

    Header file for a PLIP interface driver

  June 2026 - Created

*************************************************************************** */

#ifndef __PLIP_H__
#define __PLIP_H__

#include    <stdint.h>

#include    "ip/error.h"
#include    "ip/types.h"

/* -----------------------------------------
   PLIP interface data structure
----------------------------------------- */
struct plip_t
{
    uint16_t    nextPacket;
    uint16_t    currentLength;
};

/* -----------------------------------------
   interface functions
----------------------------------------- */
struct plip_t*       plip_init(void);
void                 plip_close(void);
ip4_err_t            plip_output(struct net_interface_t* const, struct pbuf_t* const);
struct pbuf_t* const plip_input(struct net_interface_t* const);
int                  plip_link_state(void);

#endif  /* __PLIP_H__ */

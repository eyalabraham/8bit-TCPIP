/*
 * dnsresolve.h
 *
 *  DNS resolver library module.
 *  The DNS resolve module will look for DNS1 and optional DNS2
 *  DOS environment variables. The function will fail if these are
 *  not defined and no alternate DNS server IP is provided.
 *  The module supports the following RR types:
 *      'A' host IP address and reverse IP resolution
 *      'MX' Mail exchange
 *      'CNAME' Canonical host name
 *
 */

#ifndef __DNSRESOLVE_H__
#define __DNSRESOLVE_H__

#include    "ip/types.h"

// Query result code
#define     FLAG_RC_OK              0
#define     FLAG_RC_FORMAT_ERR      1
#define     FLAG_RC_SRVR_FAIL       2
#define     FLAG_RC_NAME_ERR        3
#define     FLAG_RC_NOT_IMPLEMENTED 4
#define     FLAG_RC_REFUSED         5
#define     FLAG_RC_YX_DOMAIN       6
#define     FLAG_RC_YX_RR_SET       7
#define     FLAG_RC_NX_RR_SET       8
#define     FLAG_RC_NOT_AUTH        9
#define     FLAG_RC_NOT_ZONE        10

#define     MAX_HOST_NAME_LEN       256

typedef enum
{
    T_A     = 1,        // IPv4 address
    T_NS    = 2,        // Name server
    T_CNAME = 5,        // Canonical name
    T_SOA   = 6,        // Start of authority zone
    T_PTR   = 12,       // Domain name pointer
    T_MX    = 15,       // Mail server
    T_TXT   = 16        // Text
} type_t;

struct hostent_t
{
    char    h_names[MAX_HOST_NAME_LEN];     // Official name of host
    char    h_aliases[MAX_HOST_NAME_LEN];   // Alias or IPv4 address (string in dot-notation)
    type_t  h_type;                         // Type of relationship
};

struct dns_resolution_t
{
    int                h_list_len;  // Available length of list
    int                h_error;     // Query result code
    struct hostent_t  *h_info_list;
};

typedef enum
{
    DNS_OK = 0,         // Query results complete
    DNS_LIST_TRUNC = 1, // Partial results in 'hostent_t', insufficient space
    DNS_NO_SOA = 2,     // SOA info in answer was not parsed
    DNS_STACK_ERR = 3,  // No results, stack error check 'h_error' member of 'dns_resolution_t'
    DNS_TIME_OUT = 4,   // No results, server time-out check 'h_error' member of 'dns_resolution_t'
    DNS_NO_RESULTS = 5, // No DNS results in response, check 'h_error' member of 'dns_resolution_t'
    DNS_NO_SERVER = 6,  // No defined name server in environment
    DNS_NOT_SET = -1    // Value not valid
} dns_result_t;

dns_result_t dnsresolve_gethostbyname(char*, struct dns_resolution_t*);
dns_result_t dnsresolve_gethostbyaddr(ip4_addr_t, struct dns_resolution_t*);
dns_result_t dnsresolve_gethostbynameEx(char*, type_t, ip4_addr_t, struct dns_resolution_t*);

#endif  /* __DNSRESOLVE_H__ */

/*
 * dnsresolve.c
 *
 *  DNS resolver library module for DOS on PC-XT.
 *  The DNS resolve module will look for DNS1 and optional DNS2
 *  DOS environment variables. The function will fail if these are
 *  not defined and no alternate DNS server IP is provided.
 *  The module supports the following RR types:
 *      'A' host IP address and reverse IP resolution.
 *
 */

#define     DEBUG                   0

#define     __STDC_WANT_LIB_EXT1__  1               // safe library function calls

#include    <stdio.h>
#include    <string.h>
#include    <stdlib.h>
#include    <assert.h>

#include    "ip/netif.h"
#include    "ip/stack.h"
#include    "ip/udp.h"
#include    "ip/error.h"
#include    "ip/types.h"
#include    "ip/dnsresolve.h"

#include    "ip/slip.h"     // TODO for slip_close(), remove once this is in a stack_close() call

/* -----------------------------------------
   definitions
----------------------------------------- */
#define     DNS_STATE_REQUEST       1               // Send a request
#define     DNS_STATE_WAIT_RESP     2               // Wait for a response
#define     DNS_STATE_COMPLETE      3               // Response received and processed

// DNS header flags1
#define     FLAG_RD                 1
#define     FLAG_TC                 2
#define     FLAG_AA                 4
#define     FLAG_OPC_STDQ           0
#define     FLAG_OPC_INVQ           8
#define     FLAG_OPC_SRVSTAT        16
#define     FLAG_OPC_NOTIFY         32
#define     FLAG_OPC_UPDATE         40
#define     FLAG_QR                 128

// DNS header flags2
#define     RC_MASK                 0x0f
#define     FLAG_RA                 128

// DNS miscellaneous
#define     DNS_PAYLOAD_SIZE        512             // Maximum for DNS over UDP
#define     DNS_PORT                53
#define     MY_PORT                 (30000+DNS_PORT)
#define     DNS_REQUEST_TIMEOUT     5000            // 5 seconds

#define     INTERNET_CLASS          1

/* -----------------------------------------
   Function Prototypes
----------------------------------------- */
static int   dnsresolve_get_rr(struct dns_header_t*, uint8_t*, struct hostent_t*);
static void  dnsresolve_response(struct pbuf_t* const, const ip4_addr_t, const uint16_t);
static int   dnsresolve_dnsname_to_host(uint8_t*, char*, int);
static int   dnsresolve_get_dnsname(uint8_t*, uint8_t*, char*, int, int);
static int   dnsresolve_host_to_dnsname(char*, char*, int);

/* -----------------------------------------
   types and data structures
----------------------------------------- */

typedef struct dns_header_t
{
    uint16_t    id;         // Identification number
    uint8_t     flags1;     // flags
/*              b7.b6.b5.b4.b3.b2.b1.b0
 *              |  |  |  |  |  |  |  |
 *              |  |  |  |  |  |  |  +---- RD: 1=Recursion desired, 0=No recursion
 *              |  |  |  |  |  |  +------- TC: 1=Message is truncated try TCP, 0=Message is complete
 *              |  |  |  |  |  +---------- AA: Authoritative answer
 *              |  |  |  |  +------------- OP0:
 *              |  |  |  +---------------- OP1: 0=Standard query, 1=Inverse qury, 2=Server status query,
 *              |  |  +------------------- OP2: 3=Reserved, 4=Notify, 5=Update
 *              |  +---------------------- OP3:
 *              +------------------------- QR: 0=Query, 1=Response
 */
    uint8_t     flags2;
/*              b7.b6.b5.b4.b3.b2.b1.b0
 *              |  |  |  |  |  |  |  |
 *              |  |  |  |  |  |  |  +---- RC0:
 *              |  |  |  |  |  |  +------- RC1: Response codes
 *              |  |  |  |  |  +---------- RC2:
 *              |  |  |  |  +------------- RC3:
 *              |  |  |  +---------------- '0'
 *              |  |  +------------------- '0'
 *              |  +---------------------- '0'
 *              +------------------------- RA: 1=Recursion available, 0=Recursion not available
 */
    uint16_t    q_count;    // Question count
    uint16_t    ans_count;  // Answer count
    uint16_t    auth_count; // Authority records count
    uint16_t    add_count;  // Additional records count
};

/* -----------------------------------------
   globals
----------------------------------------- */
static int          dns_request_state;
static uint8_t      dnsPayload[DNS_PAYLOAD_SIZE];
static uint8_t      dnsName[MAX_HOST_NAME_LEN];
static char         ip[16];         // For 'nnn.nnn.nnn.nnn\0' IP address
static char         arpa_name[32];  // For 'nnn.nnn.nnn.nnn.in-addr.arpa\0' name

/*------------------------------------------------
 * dnsresolve_gethostbyname()
 *
 *  Perform an address DNS query
 *
 * param:  Pointer to host name string and pointer to response structure
 * return: Enumerated resolution result, NS query result populated in 'dns_resolution_t' passed by reference
 *
 */
dns_result_t dnsresolve_gethostbyname(char *host_name, struct dns_resolution_t *host_info)
{
    ip4_addr_t  name_server = 0;

    if ( !stack_ip4addr_getenv("DNS", &name_server) )
    {
        host_info->h_error = FLAG_RC_SRVR_FAIL;
        return DNS_NO_SERVER;
    }

    return dnsresolve_gethostbynameEx(host_name, T_A, name_server, host_info);
}

/*------------------------------------------------
 * dnsresolve_gethostbyaddr()
 *
 *  Perform a reverse address lookup
 *
 * param:  IPv4 to look up, and pointer to response structure
 * return: Enumerated resolution result, NS query result populated in 'dns_resolution_t' passed by reference
 *
 */
dns_result_t dnsresolve_gethostbyaddr(ip4_addr_t resolve_ip, struct dns_resolution_t *host_info)
{
    ip4_addr_t  name_server = 0;

    if ( !stack_ip4addr_getenv("DNS", &name_server) )
    {
        host_info->h_error = FLAG_RC_SRVR_FAIL;
        return DNS_NO_SERVER;
    }

    stack_ip4addr_ntoa(resolve_ip, ip, sizeof(ip));

    return dnsresolve_gethostbynameEx(ip, T_A, name_server, host_info);
}

/*------------------------------------------------
 * dnsresolve_gethostbyname()
 *
 *  Perform a DNS query
 *
 * param:  Pointer to host name string, query type, DNS server address, and pointer to response structure
 * return: Enumerated resolution result, NS query result populated in 'dns_resolution_t' passed by reference
 *
 */
dns_result_t dnsresolve_gethostbynameEx(char *host_name,
                                        type_t query_type, ip4_addr_t dns_server_address,
                                        struct dns_resolution_t *host_info)
{
    int                     i;
    int                     dns_answers;
    int                     rr_offset_increment;

    struct net_interface_t *netif;
    struct udp_pcb_t       *dns;
    int                     linkState;
    ip4_err_t               result;
    uint32_t                lastDnsRequest;

    struct dns_header_t    *dnsHeader;          // DNS header
    uint8_t                *question_name;      // Variable length name
    uint16_t               *question_type_class;
    uint8_t                *dnsRRs;
    int                     name_length;

    dns_result_t            gethostbynameEx_result = DNS_OK;
    int                     done = 0;

    ip4_addr_t              temp_ipv4;
    ip4_addr_t              gateway = 0;
    ip4_addr_t              net_mask = 0;
    ip4_addr_t              local_host = 0;

    /* Initialize IP stack
     */
    if ( !stack_ip4addr_getenv("GATEWAY", &gateway) )
    {
        host_info->h_error = ERR_NETIF;
        return DNS_STACK_ERR;
    }

    if ( !stack_ip4addr_getenv("NETMASK", &net_mask) )
    {
        host_info->h_error = ERR_NETIF;
        return DNS_STACK_ERR;
    }

    if ( !stack_ip4addr_getenv("LOCALHOST", &local_host) )
    {
        host_info->h_error = ERR_NETIF;
        return DNS_STACK_ERR;
    }

    stack_init();                                       // initialize IP stack
    assert(stack_set_route(net_mask,
                           gateway,
                           0) == ERR_OK);               // setup default route
    netif = stack_get_ethif(0);                         // get pointer to interface 0
    assert(netif);

    assert(interface_slip_init(netif) == ERR_OK);       // initialize interface and link HW
    interface_set_addr(netif, local_host,               // setup static IP addressing
                              net_mask,
                              gateway);

    /* Test link state and send gratuitous ARP
     */
    linkState = interface_link_state(netif);

    /* Prepare UDP protocol and initialize for DNS
     */
    udp_init();
    dns = udp_new();
    assert(dns);
    assert(udp_bind(dns, IP4_ADDR(10,0,0,19), MY_PORT) == ERR_OK);
    assert(udp_recv(dns, dnsresolve_response) == ERR_OK);
    lastDnsRequest = 0;

    dns_request_state = DNS_STATE_REQUEST;

    /* Modify host to an ARPA reverse lookup format
     * if the host name is an IPv4 address.
     */
    if ( stack_ip4addr_aton(host_name, &temp_ipv4) )
    {
        temp_ipv4 = stack_ntohl(temp_ipv4); // This will effectively reverse the digits
        stack_ip4addr_ntoa(temp_ipv4, arpa_name, sizeof(arpa_name));
        strcat_s(arpa_name, sizeof(arpa_name), ".in-addr.arpa");
        host_name = arpa_name;
        query_type = T_PTR;
    }

#if ( DEBUG )
        printf("host_name='%s' query_type=%d\n", host_name, query_type);
#endif

    while ( !done && linkState )
    {
        /* Periodically poll link state and if a change occurred from the last
         * test propagate the notification
         */
        if ( interface_link_state(netif) != linkState )
        {
            linkState = interface_link_state(netif);
#if ( DEBUG )
            printf("Link state change, now = '%s'\n", linkState ? "up" : "down");
#endif
        }

        /* Periodically poll for received frames,
         * drop or feed them up the stack for processing
         */
        interface_input(netif);

        /* Cyclic timer update and check
         */
        stack_timers();

        /* Send an NTP request
         */
        if ( dns_request_state == DNS_STATE_REQUEST )
        {
            lastDnsRequest = stack_time();

            // Construct DNS header
            dnsHeader = (struct dns_header_t *) &dnsPayload[0];
            dnsHeader->id = stack_ntoh(lastDnsRequest);
            dnsHeader->flags1 = FLAG_RD;
            dnsHeader->flags2 = 0;
            dnsHeader->q_count = stack_hton(1);
            dnsHeader->ans_count = 0;
            dnsHeader->auth_count = 0;
            dnsHeader->add_count = 0;

            // Construct DNS query
            name_length = dnsresolve_host_to_dnsname(host_name, dnsName, sizeof(dnsName));
            memcpy_s(&dnsPayload[sizeof(struct dns_header_t)], sizeof(dnsName), dnsName, name_length);

            question_type_class = (uint16_t *) &dnsPayload[(sizeof(struct dns_header_t) + name_length)];
            *question_type_class = stack_hton(query_type);
            question_type_class++;
            *question_type_class = stack_hton(INTERNET_CLASS);

            // TODO Additional records indicating capabilities
/*            Additional records
                <Root>: type OPT
                    Name: <Root>
                    Type: OPT (41)
                    UDP payload size: 512
                    Higher bits in extended RCODE: 0x00
                    EDNS0 version: 0
                    Z: 0x0000
                        0... .... .... .... = DO bit: Cannot handle DNSSEC security RRs
                        .000 0000 0000 0000 = Reserved: 0x0000
                    Data length: 0
*/

            question_type_class++;  // Increment to point to where the RR responses will start

            // Send DNS query
            result = udp_sendto(dns, (uint8_t*) dnsPayload,
                                sizeof(struct dns_header_t) + name_length + sizeof(uint16_t) + sizeof(uint16_t),
                                dns_server_address, DNS_PORT);

            if ( result == ERR_OK ||
                 result == ERR_ARP_QUEUE )
            {
                /* Wait for DNS response
                 */
                dns_request_state = DNS_STATE_WAIT_RESP;
            }
            else
            {
                host_info->h_error = result;
                gethostbynameEx_result = DNS_STACK_ERR;
                done = 1;
            }
        }

        /* Wait for DNS response and check time out.
         */
        else if ( dns_request_state == DNS_STATE_WAIT_RESP )
        {
            if ( (stack_time() - lastDnsRequest) > DNS_REQUEST_TIMEOUT )
            {
                host_info->h_error = result;
                gethostbynameEx_result = DNS_TIME_OUT;
                done = 1;
            }
        }

        /* Got response, process it and exit
         */
        else if ( dns_request_state == DNS_STATE_COMPLETE )
        {
#if ( DEBUG )
            printf("DNS response:\n");
            printf(" Response is %struncated\n", (dnsHeader->flags1 & FLAG_TC) ? "" : "not ");
            printf(" Response is %sauthoritative\n", (dnsHeader->flags1 & FLAG_AA) ? "" : "not ");
            printf(" Response code %u\n", (dnsHeader->flags2 & RC_MASK));
            printf(" Questions %u\n", stack_ntoh(dnsHeader->q_count));
            printf(" Answers %u\n", stack_ntoh(dnsHeader->ans_count));
            printf(" Authoritative servers %u\n", stack_ntoh(dnsHeader->auth_count));
            printf(" Additional records %u\n\n", stack_ntoh(dnsHeader->add_count));
#endif
            host_info->h_error = (int) (dnsHeader->flags2 & RC_MASK);
            dns_answers = (int) stack_ntoh(dnsHeader->ans_count);

            if ( dns_answers == 0 )
            {
                gethostbynameEx_result = DNS_NO_RESULTS;
            }
            else
            {
                dnsRRs = (uint8_t *) question_type_class;

                for ( i = 0; i < dns_answers && i < host_info->h_list_len; i++)
                {
                    rr_offset_increment = dnsresolve_get_rr(dnsHeader, dnsRRs, &host_info->h_info_list[i]);
                    dnsRRs += rr_offset_increment;
                }

                host_info->h_list_len = dns_answers;

                if ( dns_answers > host_info->h_list_len )
                    gethostbynameEx_result = DNS_LIST_TRUNC;
            }

            done = 1;
        }
    }

    slip_close();

    return gethostbynameEx_result;
}

/*------------------------------------------------
 * dnsresolve_get_rr()
 *
 *  Parse and return RR information pointed to by record start pointer.
 *
 * param:  pointer to DNS header, RR to parse, and host entity to update
 * return: length of parsed record in bytes.
 *
 */
int dnsresolve_get_rr(struct dns_header_t *dns_header, uint8_t *resource_record, struct hostent_t *host_entity)
{
    static char rr_object_name[MAX_HOST_NAME_LEN];

    int         i, rr_data_length;

    uint16_t    temp;
    ip4_addr_t  host_address;

    int         rr_length = 0;

    // Recursively compile the full DNS-formatted name
    memset(rr_object_name, 0, sizeof(rr_object_name));
    rr_length = dnsresolve_get_dnsname((uint8_t*)dns_header, resource_record, rr_object_name, 0, sizeof(rr_object_name));
    dnsresolve_dnsname_to_host(rr_object_name, host_entity->h_names, sizeof(host_entity->h_names));

    // Store RR type
    temp = *((uint16_t*)(resource_record + rr_length));
    host_entity->h_type = (type_t) stack_ntoh(temp);
#if ( DEBUG )
    printf("host_entity->h_type=%u rr_length=%d\n", (uint16_t)host_entity->h_type, rr_length);
#endif
    rr_length += 8;

    // Get and store RR alias or IPv4 data
    temp = *((uint16_t*)(resource_record + rr_length));
    rr_data_length = stack_ntoh(temp);
#if ( DEBUG )
    printf("rr_data_length=%d rr_length=%d\n", rr_data_length, rr_length);
#endif
    rr_length += 2;

    // Handle the resource data according to resource type
    switch ( host_entity->h_type )
    {
        case T_A:
            host_address = *((ip4_addr_t*)(resource_record + rr_length));
            stack_ip4addr_ntoa(host_address, ip, sizeof(ip));
            strcpy_s(host_entity->h_aliases, sizeof(host_entity->h_aliases), ip);
            break;

        case T_NS:
            break;

        case T_CNAME:
        case T_PTR:
        case T_MX:
            memset(rr_object_name, 0, sizeof(rr_object_name));
            dnsresolve_get_dnsname((uint8_t*)dns_header, (resource_record + rr_length),
                                   rr_object_name, 0, sizeof(rr_object_name));
            dnsresolve_dnsname_to_host(rr_object_name, host_entity->h_aliases, sizeof(host_entity->h_aliases));
            break;

        case T_SOA:
            break;

        case T_TXT:
            memset(rr_object_name, 0, sizeof(rr_object_name));
            memcpy_s(host_entity->h_aliases, sizeof(host_entity->h_aliases) - 1,
                     (resource_record + rr_length), rr_data_length);
            break;

        default:;
    }

    rr_length += rr_data_length;

    return rr_length;
}

/*------------------------------------------------
 * dnsresolve_response()
 *
 *  Callback to receive DNS server responses
 *
 * param:  pointer to response pbuf, source IP address and source port
 * return: none
 *
 */
void dnsresolve_response(struct pbuf_t* const p, const ip4_addr_t srcIP, const uint16_t srcPort)
{
    uint8_t    *dnsResponse;

    // Crude way to get pointer the DNS response payload
    dnsResponse = (uint8_t *) &(p->pbuf[FRAME_HDR_LEN+IP_HDR_LEN+UDP_HDR_LEN]);

    memcpy_s(dnsPayload, sizeof(dnsPayload), dnsResponse, sizeof(dnsPayload));

    dns_request_state = DNS_STATE_COMPLETE;
}

/*------------------------------------------------
 * dnsresolve_dnsname_to_host()
 *
 *  Convert DNS name format to dot-name format.
 *  The functions parses the data from the DNS response,
 *  accounting for DNS name compression.
 *
 * param:  Pointer to DNS name in current RR, output host name string and its buffer length,
 *         and pointer to DNS packet holding other parts of the name
 * return: 0=conversion error, >0=conversion ok and is length of converted name string
 *
 */
int dnsresolve_dnsname_to_host(uint8_t *dns_format_name, char *host_format_name, int name_buf_length)
{
    int     i, j, k;
    int     segment_length;

    // Convert DNS notation to dot notation
    i = 0;
    k = 0;
    while ( dns_format_name[i]  && k < name_buf_length )
    {
        segment_length = dns_format_name[i++];
        for ( j = 0; j < segment_length; j++)
        {
            host_format_name[k++] = dns_format_name[i++];
        }
        host_format_name[k++] = '.';
    }

    if ( k > 0 )
        host_format_name[--k] = '\0';    // Remove extra trailing '.'

#if ( DEBUG )
    printf("'%s' -> '%s'\n", dns_format_name, host_format_name);
#endif

    return k;
}

/*------------------------------------------------
 * dnsresolve_get_dnsname()
 *
 *  Recursively compile the full DNS-formatted name
 *  from the RR, and account for name compression/deduplication.
 *
 * param:  Pointer to DNS response,
 *         pointer to DNS name in current RR,
 *         output DNS name string, index to it and its length,
 * return: 0=conversion error, >0=conversion ok and is length of compiled DNS name string
 *
 */
int dnsresolve_get_dnsname(uint8_t *dns_response,
                           uint8_t *rr_dns_name,
                           char *dns_name, int dns_name_buf_idx, int dns_name_buf_len)
{
    int     i;
    int     dedup_segment_index;

    for ( i = 0;  i < dns_name_buf_len; i++ )
    {
        // The 0xC0 dedup marker can only appear alone or at the end of a string
        if ( (rr_dns_name[i] & 0xc0) == 0xc0 )
        {
            dedup_segment_index = (int)(((rr_dns_name[i] & 0x3f) << 8) + rr_dns_name[i+1]);
            dnsresolve_get_dnsname(dns_response, &dns_response[dedup_segment_index],
                                   dns_name, (dns_name_buf_idx + i), (dns_name_buf_len - (dns_name_buf_idx + i)));
            i += 2;
            break;
        }
        // Break on terminating zero if a string does not have a dedup marker
        else if ( rr_dns_name[i] == 0 )
        {
            i++;
            break;
        }
        else
        {
            dns_name[(dns_name_buf_idx + i)] = rr_dns_name[i];
        }
    }

    /* This return value is one used when the first call of the
     * recursion returns. It reflects the number of bytes in the *original*
     * RR name that was parsed by this function.
     */
    return i;
}


/*------------------------------------------------
 * dnsresolve_host_to_dnsname()
 *
 *  Convert dot-name format to DNS name format.
 *
 * param:  String pointer to host name string, pointer to DNS name format, and its buffer length
 * return: Length of converted name string
 *         A length of 1 is an error because it is the terminating 0, transferring this
 *         to the name server will ultimately result in a DNS name error 'FLAG_RC_NAME_ERR'
 *
 */
int dnsresolve_host_to_dnsname(char *host_format, char *dns_format, int name_buf_length)
{
    int     char_index = 0;
    int     i = 0;
    int     segment_count = 0;

    // Reverse the source name string and convert
    strrev(host_format);

    while ( char_index < name_buf_length )
    {
        if ( host_format[i] == '.' || host_format[i] == '@' )
        {
            dns_format[char_index] = (uint8_t) segment_count;
            segment_count = 0;
        }
        else if ( host_format[i] == '\0' )
        {
            dns_format[char_index] = (uint8_t) segment_count;
            char_index++;
            break;
        }
        else
        {
            dns_format[char_index] = host_format[i];
            segment_count++;
        }

        char_index++;
        i++;
    }

    // Terminate or truncate the DNS name format
    if ( char_index < name_buf_length )
    {
        dns_format[char_index] = '\0';
    }
    else
    {
        dns_format[0] = '\0';
    }

    // Reverse the result and return its length including zero-termination
    strrev(dns_format);

    // Restore the input string to original state
    strrev(host_format);

    return (strlen(dns_format) + 1);
}

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>

#define HAVE_NETINET_SCTP_H             1

#define OGS_CORE_INSIDE                 1
#include "srsran/support/io/ogs-sockaddr.h"

#define OGS_MAX_SDU_LEN                 32768 /* Should Heap */
#define OGS_OK           0
#define OGS_ERROR       -1
#define true            1
#define OGS_POLLOUT     0x02
//#define INET_ADDRSTRLEN  16
#define INET6_ADDRSTRLEN 46
#define OGS_ADDRSTRLEN INET6_ADDRSTRLEN

typedef int ogs_socket_t;
typedef struct ogs_sockaddr_s ogs_sockaddr_t;
// struct ogs_sockaddr_s {
//     /* Reserved Area
//      *   - Should not add any atrribute in this area.
//      *
//      *   e.g)
//      *   struct sockaddr addr;
//      *   ...
//      *   sockaddr_len((ogs_sockaddr_t *)&addr);
//      */
// #define ogs_sa_family sa.sa_family
// #define ogs_sin_port sin.sin_port
//     union {
//         struct sockaddr_storage ss;
//         struct sockaddr_in sin;
//         struct sockaddr_in6 sin6;
//         struct sockaddr sa;
//     };

//     /*
//      * First we created a 'hostname' variable.
//      * If there is a name in the configuration file,
//      * it is set in the 'hostname' of ogs_sockaddr_t.
//      * Then, it immediately call getaddrinfo() to fill addr in ogs_sockaddr_t.
//      *
//      * When it was always possible to convert DNS to addr, that was no problem.
//      * However, in some environments, such as Roaming, there are situations
//      * where it is difficult to always change the DNS to addr.
//      *
//      * So, 'fqdn' was created for the purpose of first use in ogs_sbi_client_t.
//      * 'fqdn' always do not change with addr.
//      * This value is used as it is in the actual client connection.
//      *
//      * Note that 'hostname' is still in use for server or other client
//      * except for ogs_sbi_client_t.
//      */
//     char *hostname;
//     char *fqdn;

//     ogs_sockaddr_t *next;
// };
// typedef struct ogs_sock_s {
//     int family;
//     ogs_socket_t fd;

//     ogs_sockaddr_t local_addr;
//     ogs_sockaddr_t remote_addr;
// } ogs_sock_t;

struct ogs_list_s {
    struct ogs_list_s *prev, *next;
};
typedef struct ogs_pollset_s ogs_pollset_t;
typedef struct ogs_list_s ogs_lnode_t;
typedef void (*ogs_poll_handler_f)(short when, ogs_socket_t fd, void *data);
typedef struct ogs_list_s ogs_list_t;

typedef struct ogs_poll_s {
    ogs_lnode_t node;
    int index;

    short when;
    ogs_socket_t fd;
    ogs_poll_handler_f handler;
    void *data;

    ogs_pollset_t *pollset;
} ogs_poll_t;

typedef struct ogs_sockopt_s {
    struct {
        uint32_t spp_hbinterval;
        uint32_t spp_sackdelay;
        uint32_t srto_initial;
        uint32_t srto_min;
        uint32_t srto_max;
#define OGS_DEFAULT_SCTP_MAX_NUM_OF_OSTREAMS 30
        uint16_t sinit_num_ostreams;
        uint16_t sinit_max_instreams;
        uint16_t sinit_max_attempts;
        uint16_t sinit_max_init_timeo;
    } sctp;

    bool sctp_nodelay;
    bool tcp_nodelay;

    struct {
        bool l_onoff;
        int l_linger;
    } so_linger;

    const char *so_bindtodevice;
} ogs_sockopt_t;

typedef struct ogs_cluster_s {
    unsigned char *buffer;
    unsigned int size;

    unsigned int reference_count;
} ogs_cluster_t;

typedef void ogs_pkbuf_pool_t;

typedef struct ogs_pkbuf_s {
    ogs_lnode_t lnode;

    /* Currently it is used in SCTP stream number and PPID. */
    uint64_t param[2];

    ogs_cluster_t *cluster;

    unsigned int len;

    unsigned char *head;
    unsigned char *tail;
    unsigned char *data;
    unsigned char *end;

    const char *file_line;
    
    ogs_pkbuf_pool_t *pool;

    unsigned char _data[0]; /*!< optional immediate data array */
} ogs_pkbuf_t;

#define ogs_inline __inline__
static ogs_inline void *ogs_list_first(const ogs_list_t *list)
{
    return list->next;
}
static ogs_inline void *ogs_list_next(void *lnode)
{
    ogs_list_t *node = (ogs_list_t *)lnode;
    return node->next;
}
#define ogs_list_for_each_safe(list, n, node) \
    for (node = ogs_list_first(list); \
        (node) && (n = ogs_list_next(node), 1); \
        node = n)

static ogs_inline void ogs_list_remove(ogs_list_t *list, void *lnode)
{
    ogs_list_t *node = (ogs_list_t *)lnode;
    ogs_list_t *prev = node->prev;
    ogs_list_t *next = node->next;

    if (prev)
        prev->next = next;
    else
        list->next = next;

    if (next)
        next->prev = prev;
    else
        list->prev = prev;
}
static ogs_inline bool ogs_list_empty(const ogs_list_t *list)
{
    return list->next == NULL;
}
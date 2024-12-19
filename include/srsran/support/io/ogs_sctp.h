/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef OGS_SCTP_H
#define OGS_SCTP_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>

#define OGS_CORE_INSIDE                 1
#define OGS_MAX_SDU_LEN                 32768 /* Should Heap */
#define OGS_OK                          0
#define OGS_ERROR                       -1
#define true                            1
#define OGS_POLLOUT                     0x02
#define INET6_ADDRSTRLEN                46
#define OGS_ADDRSTRLEN                  INET6_ADDRSTRLEN

typedef int ogs_socket_t;
typedef struct ogs_sockaddr_s ogs_sockaddr_t;
struct ogs_sockaddr_s {
    /* Reserved Area
     *   - Should not add any atrribute in this area.
     *
     *   e.g)
     *   struct sockaddr addr;
     *   ...
     *   sockaddr_len((ogs_sockaddr_t *)&addr);
     */
#define ogs_sa_family sa.sa_family
#define ogs_sin_port sin.sin_port
    union {
        struct sockaddr_storage ss;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
        struct sockaddr sa;
    };

    /*
     * First we created a 'hostname' variable.
     * If there is a name in the configuration file,
     * it is set in the 'hostname' of ogs_sockaddr_t.
     * Then, it immediately call getaddrinfo() to fill addr in ogs_sockaddr_t.
     *
     * When it was always possible to convert DNS to addr, that was no problem.
     * However, in some environments, such as Roaming, there are situations
     * where it is difficult to always change the DNS to addr.
     *
     * So, 'fqdn' was created for the purpose of first use in ogs_sbi_client_t.
     * 'fqdn' always do not change with addr.
     * This value is used as it is in the actual client connection.
     *
     * Note that 'hostname' is still in use for server or other client
     * except for ogs_sbi_client_t.
     */
    char *hostname;
    char *fqdn;

    ogs_sockaddr_t *next;
};
typedef struct ogs_sock_s {
    int family;
    ogs_socket_t fd;

    ogs_sockaddr_t local_addr;
    ogs_sockaddr_t remote_addr;
} ogs_sock_t;

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

#define OGS_SCTP_INSIDE

/* Nothing */

#undef OGS_SCTP_INSIDE

#ifdef __cplusplus
extern "C" {
#endif

extern int __ogs_sctp_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __ogs_sctp_domain

#define OGS_S1AP_SCTP_PORT              36412
#define OGS_SGSAP_SCTP_PORT             29118
#define OGS_NGAP_SCTP_PORT              38412

#define OGS_SCTP_S1AP_PPID              18
#define OGS_SCTP_X2AP_PPID              27
#define OGS_SCTP_SGSAP_PPID             0
#define OGS_SCTP_NGAP_PPID              60

#define ogs_sctp_ppid_in_pkbuf(__pkBUF)         (__pkBUF)->param[0]
#define ogs_sctp_stream_no_in_pkbuf(__pkBUF)    (__pkBUF)->param[1]

#if HAVE_USRSCTP

#undef MSG_NOTIFICATION
#define MSG_NOTIFICATION 0x2000

#ifndef INET
#define INET            1
#endif
#ifndef INET6
#define INET6           1
#endif


#else

#ifdef __LINUX__
#include <netinet/sctp.h>
#endif
#ifdef __APPLE__
#include <usrsctp.h>
ogs_sockaddr_t *ogs_usrsctp_remote_addr(union sctp_sockstore *store);
void ogs_sctp_destroy(ogs_sock_t *sock);
ogs_sock_t *ogs_sctp_accept(ogs_sock_t *sock);
#endif


#define ogs_sctp_destroy ogs_sock_destroy
#define ogs_sctp_accept ogs_sock_accept

#endif

typedef struct ogs_sctp_sock_s {
    int             type;           /* SOCK_STREAM or SOCK_SEQPACKET */

    ogs_sock_t      *sock;          /* Socket */
    ogs_sockaddr_t  *addr;          /* Address */

    struct {
        ogs_poll_t  *read;          /* Read Poll */
        ogs_poll_t  *write;         /* Write Poll */
    } poll;

    ogs_list_t      write_queue;    /* Write Queue for Sending S1AP message */
} ogs_sctp_sock_t;

typedef struct ogs_sctp_info_s {
    uint32_t ppid;
    uint16_t stream_no;
    uint16_t inbound_streams;
    uint16_t outbound_streams;
} ogs_sctp_info_t;

void ogs_sctp_init(uint16_t port);
void ogs_sctp_final(void);

ogs_sock_t *ogs_sctp_socket(int family, int type);

ogs_sock_t *ogs_sctp_server(
        int type, ogs_sockaddr_t *sa_list, ogs_sockopt_t *socket_option);
ogs_sock_t *ogs_sctp_client(
        int type, ogs_sockaddr_t *sa_list, ogs_sockopt_t *socket_option);

int ogs_sctp_bind(ogs_sock_t *sock, ogs_sockaddr_t *sa_list);
int ogs_sctp_connect(ogs_sock_t *sock, ogs_sockaddr_t *sa_list);
int ogs_sctp_listen(ogs_sock_t *sock);

int ogs_sctp_peer_addr_params(ogs_sock_t *sock, ogs_sockopt_t *option);
int ogs_sctp_rto_info(ogs_sock_t *sock, ogs_sockopt_t *option);
int ogs_sctp_initmsg(ogs_sock_t *sock, ogs_sockopt_t *option);
int ogs_sctp_nodelay(ogs_sock_t *sock, int on);
int ogs_sctp_so_linger(ogs_sock_t *sock, int l_linger);

int ogs_sctp_sendmsg(ogs_sock_t *sock, const void *msg, size_t len,
        ogs_sockaddr_t *to, uint32_t ppid, uint16_t stream_no);
int ogs_sctp_recvmsg(ogs_sock_t *sock, void *msg, size_t len,
        ogs_sockaddr_t *from, ogs_sctp_info_t *sinfo, int *msg_flags);
int ogs_sctp_recvdata(ogs_sock_t *sock, void *msg, size_t len,
        ogs_sockaddr_t *from, ogs_sctp_info_t *sinfo);

int ogs_sctp_senddata(ogs_sock_t *sock,
        ogs_pkbuf_t *pkbuf, ogs_sockaddr_t *addr);
void ogs_sctp_write_to_buffer(ogs_sctp_sock_t *sctp, ogs_pkbuf_t *pkbuf);
void ogs_sctp_flush_and_destroy(ogs_sctp_sock_t *sctp);

int ogs_getaddrinfo(ogs_sockaddr_t **sa_list,
        int family, const char *hostname, uint16_t port, int flags);
int ogs_sock_bind(ogs_sock_t *sock, ogs_sockaddr_t *addr);

static __inline__ void *ogs_list_first(const ogs_list_t *list)
{
    return list->next;
}
static __inline__ void *ogs_list_next(void *lnode)
{
    ogs_list_t *node = (ogs_list_t *)lnode;
    return node->next;
}
static __inline__ void ogs_list_remove(ogs_list_t *list, void *lnode)
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
static __inline__ bool ogs_list_empty(const ogs_list_t *list)
{
    return list->next == NULL;
}
#define ogs_list_for_each_safe(list, n, node) \
    for (node = ogs_list_first(list); \
        (node) && (n = ogs_list_next(node), 1); \
        node = n)


#ifdef __cplusplus
}
#endif

#endif /* OGS_SCTP_H */

#define _GNU_SOURCE 1

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/rtnetlink.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define DIE()             \
    {                     \
        perror(__func__); \
        abort();          \
    }
#define PKT_MAX_LEN     2048
#define BUF_SIZE        256
#define IPV4_ADDR_LEN   4
#define IPV6_ADDR_LEN   16
#define IPV6_INT32_SEGS (IPV6_ADDR_LEN / sizeof(uint32_t))
#define REPLY_TTL       233
#define TCPOPT_NOP_16B  (htons((TCPOPT_NOP << 8) + TCPOPT_NOP))

struct ip_blk {
    uint32_t af;
    uint32_t prefix_len;

    union {
        char     addr[IPV6_ADDR_LEN];
        uint32_t addr_v4;
        uint32_t addr_v6[IPV6_INT32_SEGS];
    };
};

struct pkt {
    union {
        struct {
            char         reserved[20];
            struct iphdr ipv4_padding;
        };
        struct ip6_hdr ipv6_padding;
    };
    struct icmphdr icmp_padding;
    union {
        struct {
            struct iphdr ipv4_hdr;
            union {
                struct tcphdr  tcp_hdr;
                struct icmphdr icmp_hdr;
            };
        };
        struct {
            struct ip6_hdr ipv6_hdr;
            union {
                struct tcphdr  tcp6_hdr;
                struct icmphdr icmp6_hdr;
            };
        };
    };
};

static char           ifname[IFNAMSIZ];
static struct ip_blk* ip_blks     = NULL;
uint32_t              ip_blks_len = 0;

static inline void tun_create(uint32_t cpus, int* fds) {
    struct ifreq ifr;
    int          fd, ret;

    /* allocate tun device */
    if (0 > (fd = open("/dev/net/tun", O_RDWR))) DIE();

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
    if (0 > (ret = ioctl(fd, TUNSETIFF, (void*) &ifr))) DIE();

    fds[0] = fd;

    for (uint32_t i = 1; i < cpus; i++) {
        if (0 > (fd = open("/dev/net/tun", O_RDWR))) DIE();
        if (0 > (ret = ioctl(fd, TUNSETIFF, (void*) &ifr))) DIE();
        fds[i] = fd;
    }

    strncpy(ifname, ifr.ifr_name, IFNAMSIZ);
}

static inline void if_up() {
    struct ifreq ifr;
    int          fd;

    if (0 > (fd = socket(AF_INET, SOCK_DGRAM, 0))) DIE();

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_flags = IFF_UP | IFF_RUNNING;

    if (0 > ioctl(fd, SIOCSIFFLAGS, (void*) &ifr)) DIE();

    close(fd);
}

static inline int if_get_index() {
    int  fd;
    char buf[BUF_SIZE];
    int  len;
    snprintf(buf, BUF_SIZE, "/sys/class/net/%s/ifindex", ifname);
    fd       = open(buf, O_RDONLY);
    len      = read(fd, buf, BUF_SIZE);
    buf[len] = '\0';
    close(fd);
    return atoi(buf);
}

static inline void if_addr(const uint8_t af, const char* addr, const uint32_t prefix_len) {
    struct {
        struct nlmsghdr  nh;
        struct ifaddrmsg msg;
        char             attrbuf[BUF_SIZE];
    } req;

    struct rtattr* rta;
    int            fd;
    if (0 > (fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE))) DIE();

    /* https://stackoverflow.com/questions/14369043/add-and-remove-ip-addresses-to-an-interface-using-ioctl-or-netlink
     */
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len      = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nh.nlmsg_flags    = NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST | NLM_F_ACK;
    req.nh.nlmsg_type     = RTM_NEWADDR;
    req.msg.ifa_family    = af;
    req.msg.ifa_prefixlen = prefix_len;
    req.msg.ifa_scope     = 0;
    req.msg.ifa_index     = if_get_index();
    rta                   = (struct rtattr*) (((char*) &req) + NLMSG_ALIGN(req.nh.nlmsg_len));
    rta->rta_type         = IFA_LOCAL;
    rta->rta_len          = RTA_LENGTH(af == AF_INET6 ? IPV6_ADDR_LEN : IPV4_ADDR_LEN);
    req.nh.nlmsg_len      = NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_LENGTH(af == AF_INET6 ? IPV6_ADDR_LEN : IPV4_ADDR_LEN);
    memcpy(RTA_DATA(rta), addr, af == AF_INET6 ? IPV6_ADDR_LEN : IPV4_ADDR_LEN);

    if (0 > send(fd, &req, req.nh.nlmsg_len, 0)) DIE();

    close(fd);
}

static inline uint16_t checksum_reduce(uint32_t cksum) {
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum = 0xffff - cksum;
    return (0x0000 == cksum) ? 0xffff : cksum;
}

static inline uint16_t checksum_calc(const void* buf, const uint32_t size) {
    uint32_t        cksum = 0;
    const uint16_t* b     = buf;

    for (uint32_t i = 0; i < size / 2; i++) {
        cksum += b[i];
    }
    return checksum_reduce(cksum);
}

static inline uint16_t checksum_calc_ipv6_phdr(const struct ip6_hdr* ip6, const void* buf, const uint32_t size) {
    uint32_t        cksum = 0;
    const uint16_t* b     = buf;

    for (uint32_t i = 0; i < 8; i++) {
        cksum += ip6->ip6_src.s6_addr16[i];
        cksum += ip6->ip6_dst.s6_addr16[i];
    }
    cksum += ip6->ip6_plen;
    cksum += ip6->ip6_nxt << 8;

    for (uint32_t i = 0; i < size / 2; i++) {
        cksum += b[i];
    }
    return checksum_reduce(cksum);
}

static inline void checksum_diff(uint16_t* field, const uint32_t diff) {
    uint32_t cksum = ((uint32_t) *field) - diff;
    cksum          = (cksum >> 16) + (cksum & 0xffff);
    *field         = (0x0000 == cksum) ? 0xffff : cksum;
}

/* find configured ip block to create response */
static inline uint32_t find_matching_ipv4_block(struct pkt* pkt) {
    for (uint32_t i = 0; i < ip_blks_len; i++) {
        if (ip_blks[i].af != AF_INET) continue;

        uint32_t masked_daddr = ntohl(pkt->ipv4_hdr.daddr) & (0xffffffff << (32 - ip_blks[i].prefix_len));
        uint32_t masked_ipblk = ntohl(ip_blks[i].addr_v4) & (0xffffffff << (32 - ip_blks[i].prefix_len));
        if (masked_daddr != masked_ipblk) continue;

        return ip_blks[i].addr_v4;
    }
    return 0;
}

static inline bool find_matching_ipv6_block(struct pkt* pkt, struct in6_addr* addr) {
    /* find configured ip block, create response */
    for (uint32_t i = 0; i < ip_blks_len; i++) {
        if (ip_blks[i].af != AF_INET6) continue;

        uint32_t masked_daddr;
        uint32_t masked_ipblk;

        if (ip_blks[i].prefix_len <= 32) {
            masked_daddr = ntohl(pkt->ipv6_hdr.ip6_dst.s6_addr32[0]) & (0xffffffff << (32 - ip_blks[i].prefix_len));
            masked_ipblk = ntohl(ip_blks[i].addr_v6[0]) & (0xffffffff << (32 - ip_blks[i].prefix_len));
            if (masked_daddr != masked_ipblk) continue;
        } else {
            masked_daddr = pkt->ipv6_hdr.ip6_dst.s6_addr32[0];
            masked_ipblk = ip_blks[i].addr_v6[0];
            if (masked_daddr != masked_ipblk) continue;
        }

        if (ip_blks[i].prefix_len > 32) {
            if (ip_blks[i].prefix_len <= 64) {
                masked_daddr = ntohl(pkt->ipv6_hdr.ip6_dst.s6_addr32[1]) & (0xffffffff << (64 - ip_blks[i].prefix_len));
                masked_ipblk = ntohl(ip_blks[i].addr_v6[1]) & (0xffffffff << (64 - ip_blks[i].prefix_len));
                if (masked_daddr != masked_ipblk) continue;
            } else {
                masked_daddr = pkt->ipv6_hdr.ip6_dst.s6_addr32[1];
                masked_ipblk = ip_blks[i].addr_v6[1];
                if (masked_daddr != masked_ipblk) continue;
            }
        }

        if (ip_blks[i].prefix_len > 64) {
            if (ip_blks[i].prefix_len <= 96) {
                masked_daddr = ntohl(pkt->ipv6_hdr.ip6_dst.s6_addr32[2]) & (0xffffffff << (96 - ip_blks[i].prefix_len));
                masked_ipblk = ntohl(ip_blks[i].addr_v6[2]) & (0xffffffff << (96 - ip_blks[i].prefix_len));
                if (masked_daddr != masked_ipblk) continue;

            } else {
                masked_daddr = ntohl(pkt->ipv6_hdr.ip6_dst.s6_addr32[2]);
                masked_ipblk = ntohl(ip_blks[i].addr_v6[2]);
                if (masked_daddr != masked_ipblk) continue;

                masked_daddr
                    = ntohl(pkt->ipv6_hdr.ip6_dst.s6_addr32[3]) & (0xffffffff << (128 - ip_blks[i].prefix_len));
                masked_ipblk = ntohl(ip_blks[i].addr_v6[3]) & (0xffffffff << (128 - ip_blks[i].prefix_len));
                if (masked_daddr != masked_ipblk) continue;
            }
        }

        /* Adding to higher digits is not implemented, but unlikely necessary anyway */
        memcpy(addr, ip_blks[i].addr, IPV6_ADDR_LEN);
        return true;
    }
    return false;
}

static inline bool is_ipv4_ttl_exceeded(struct pkt* pkt, uint32_t base_addr, uint32_t* timeout_addr) {
    *timeout_addr = htonl(ntohl(base_addr) + pkt->ipv4_hdr.ttl);

    return !(ntohl(base_addr) <= ntohl(pkt->ipv4_hdr.daddr)
             && ntohl(base_addr) + pkt->ipv4_hdr.ttl >= ntohl(pkt->ipv4_hdr.daddr));
}

static inline bool is_ipv6_ttl_exceeded(struct pkt* pkt, struct in6_addr* base_addr, struct in6_addr* timeout_addr) {
    memcpy(timeout_addr, base_addr, IPV6_ADDR_LEN);
    timeout_addr->s6_addr32[3] = htonl(ntohl(timeout_addr->s6_addr32[3]) + pkt->ipv6_hdr.ip6_hlim);

    return !(ntohl(base_addr->s6_addr32[3]) <= ntohl(pkt->ipv6_hdr.ip6_dst.s6_addr32[3])
             && ntohl(base_addr->s6_addr32[3]) + pkt->ipv6_hdr.ip6_hlim >= ntohl(pkt->ipv6_hdr.ip6_dst.s6_addr32[3]));
}

static inline void reply_icmp_ping(struct pkt* pkt, uint32_t pkt_len, int fd) {
    /* swap src/dst address */
    uint32_t tmp        = pkt->ipv4_hdr.daddr;
    pkt->ipv4_hdr.daddr = pkt->ipv4_hdr.saddr;
    pkt->ipv4_hdr.saddr = tmp;

    /* set pkt ttl */
    checksum_diff(&pkt->ipv4_hdr.check, REPLY_TTL - pkt->ipv4_hdr.ttl);
    pkt->ipv4_hdr.ttl = REPLY_TTL;

    /* set pkt type */
    pkt->icmp_hdr.type = ICMP_ECHOREPLY;
    /* update checksum */
    checksum_diff(&pkt->icmp_hdr.checksum, ICMP_ECHOREPLY - ICMP_ECHO);

    /* send pkt */
    if (pkt_len != write(fd, &pkt->ipv4_hdr, pkt_len)) DIE();
}

static inline void reply_tcp_syn(struct pkt* pkt, uint32_t pkt_len, int fd) {
    if (pkt->tcp_hdr.th_flags != TH_SYN) {
        /* only handle TCP SYN pkts */
        return;
    }

    /* swap src/dst address */
    uint32_t tmp        = pkt->ipv4_hdr.daddr;
    pkt->ipv4_hdr.daddr = pkt->ipv4_hdr.saddr;
    pkt->ipv4_hdr.saddr = tmp;

    /* set pkt ttl */
    checksum_diff(&pkt->ipv4_hdr.check, REPLY_TTL - pkt->ipv4_hdr.ttl);
    pkt->ipv4_hdr.ttl = REPLY_TTL;

    /* swap src/dst port */
    tmp                   = pkt->tcp_hdr.th_dport;
    pkt->tcp_hdr.th_dport = pkt->tcp_hdr.th_sport;
    pkt->tcp_hdr.th_sport = tmp;

    /* set tcp seq & ack */
    pkt->tcp_hdr.th_ack = htonl(ntohl(pkt->tcp_hdr.th_seq) + 1);
    checksum_diff(&pkt->tcp_hdr.th_sum, (pkt->tcp_hdr.th_ack >> 16) - (pkt->tcp_hdr.th_seq >> 16));
    checksum_diff(&pkt->tcp_hdr.th_sum, (pkt->tcp_hdr.th_ack & 0xffff) - (pkt->tcp_hdr.th_seq & 0xffff));
    pkt->tcp_hdr.th_seq = 0;

    /* set flags RST+ACK */
    pkt->tcp_hdr.th_flags = TH_RST | TH_ACK;
    checksum_diff(&pkt->tcp_hdr.th_sum, htons((TH_RST | TH_ACK) - TH_SYN));

    /* clear window */
    checksum_diff(&pkt->tcp_hdr.th_sum, 0 - pkt->tcp_hdr.th_win);
    pkt->tcp_hdr.th_win = 0;

    /* clear TCP options */
    uint32_t len = pkt->tcp_hdr.th_off * 4;
    for (uint32_t i = sizeof(struct tcphdr) / sizeof(uint16_t); i < len / sizeof(uint16_t); i++) {
        uint16_t* ptr = (uint16_t*) &pkt->tcp_hdr + i;
        checksum_diff(&pkt->tcp_hdr.th_sum, TCPOPT_NOP_16B - *ptr);
        *ptr = TCPOPT_NOP_16B;
    }

    /* send pkt */
    if (pkt_len != write(fd, &pkt->ipv4_hdr, pkt_len)) DIE();
}

static inline void reply_icmp_unreachable(struct pkt* pkt, uint32_t pkt_len, int fd) {
    /* populate icmp time exceed header */
    memset(&pkt->ipv4_padding, 0, 28);
    pkt->ipv4_padding.version  = 4;
    pkt->ipv4_padding.ihl      = 5;
    pkt->ipv4_padding.tot_len  = htons(56);
    pkt->ipv4_padding.ttl      = REPLY_TTL;
    pkt->ipv4_padding.protocol = IPPROTO_ICMP;

    /* copy over source addr as dest addr*/
    pkt->ipv4_padding.saddr = pkt->ipv4_hdr.daddr;
    pkt->ipv4_padding.daddr = pkt->ipv4_hdr.saddr;
    pkt->icmp_padding.type  = ICMP_DEST_UNREACH;
    pkt->icmp_padding.code  = ICMP_PORT_UNREACH;

    /* update checksum */
    pkt->ipv4_padding.check    = 0;
    pkt->ipv4_padding.check    = checksum_calc(&pkt->ipv4_padding, 20);
    pkt->icmp_padding.checksum = 0;
    pkt->icmp_padding.checksum = checksum_calc(&pkt->icmp_padding, 36);

    /* send pkt */
    pkt_len = 56;
    if (pkt_len != write(fd, &pkt->ipv4_padding, pkt_len)) DIE();
}

static inline void reply_icmp_ttl_exceeded(struct pkt* pkt, uint32_t pkt_len, int fd, uint32_t timeout_addr) {
    /* populate icmp time exceed header */
    memset(&pkt->ipv4_padding, 0, 28);
    pkt->ipv4_padding.version  = 4;
    pkt->ipv4_padding.ihl      = 5;
    pkt->ipv4_padding.tot_len  = htons(56);
    pkt->ipv4_padding.ttl      = REPLY_TTL;
    pkt->ipv4_padding.protocol = IPPROTO_ICMP;

    /* copy over source addr as dest addr*/
    pkt->ipv4_padding.saddr = timeout_addr;
    pkt->ipv4_padding.daddr = pkt->ipv4_hdr.saddr;
    pkt->icmp_padding.type  = ICMP_TIME_EXCEEDED;
    pkt->icmp_padding.code  = 0;

    /* update checksum */
    pkt->ipv4_padding.check    = 0;
    pkt->ipv4_padding.check    = checksum_calc(&pkt->ipv4_padding, 20);
    pkt->icmp_padding.checksum = 0;
    pkt->icmp_padding.checksum = checksum_calc(&pkt->icmp_padding, 36);

    /* send pkt */
    pkt_len = 56;
    if (pkt_len != write(fd, &pkt->ipv4_padding, pkt_len)) DIE();
}

static inline void reply_icmp6_ping(struct pkt* pkt, uint32_t pkt_len, int fd) {
    /* swap src/dst address */
    char tmp[IPV6_ADDR_LEN];
    memcpy(tmp, &pkt->ipv6_hdr.ip6_dst, IPV6_ADDR_LEN);
    memcpy(&pkt->ipv6_hdr.ip6_dst, &pkt->ipv6_hdr.ip6_src, IPV6_ADDR_LEN);
    memcpy(&pkt->ipv6_hdr.ip6_src, tmp, IPV6_ADDR_LEN);

    /* set pkt ttl */
    pkt->ipv6_hdr.ip6_hlim = REPLY_TTL;

    /* set pkt type */
    pkt->icmp6_hdr.type = ICMP6_ECHO_REPLY;
    /* update checksum */
    checksum_diff(&pkt->icmp6_hdr.checksum, ICMP6_ECHO_REPLY - ICMP6_ECHO_REQUEST);

    /* send pkt */
    if (pkt_len != write(fd, &pkt->ipv6_hdr, pkt_len)) DIE();
}

static inline void reply_tcp6_syn(struct pkt* pkt, uint32_t pkt_len, int fd) {
    if (pkt->tcp6_hdr.th_flags != TH_SYN) {
        /* only handle TCP SYN pkts */
        return;
    }

    /* swap src/dst address */
    char tmp[IPV6_ADDR_LEN];
    memcpy(tmp, &pkt->ipv6_hdr.ip6_dst, IPV6_ADDR_LEN);
    memcpy(&pkt->ipv6_hdr.ip6_dst, &pkt->ipv6_hdr.ip6_src, IPV6_ADDR_LEN);
    memcpy(&pkt->ipv6_hdr.ip6_src, tmp, IPV6_ADDR_LEN);

    /* set pkt ttl */
    pkt->ipv6_hdr.ip6_hlim = REPLY_TTL;

    /* swap src/dst port */
    uint32_t tmp2          = pkt->tcp6_hdr.th_dport;
    pkt->tcp6_hdr.th_dport = pkt->tcp6_hdr.th_sport;
    pkt->tcp6_hdr.th_sport = tmp2;

    /* set tcp seq & ack */
    pkt->tcp6_hdr.th_ack = htonl(ntohl(pkt->tcp6_hdr.th_seq) + 1);
    checksum_diff(&pkt->tcp6_hdr.th_sum, (pkt->tcp6_hdr.th_ack >> 16) - (pkt->tcp6_hdr.th_seq >> 16));
    checksum_diff(&pkt->tcp6_hdr.th_sum, (pkt->tcp6_hdr.th_ack & 0xffff) - (pkt->tcp6_hdr.th_seq & 0xffff));
    pkt->tcp6_hdr.th_seq = 0;

    /* set flags RST+ACK */
    pkt->tcp6_hdr.th_flags = TH_RST | TH_ACK;
    checksum_diff(&pkt->tcp6_hdr.th_sum, htons((TH_RST | TH_ACK) - TH_SYN));

    /* clear window */
    checksum_diff(&pkt->tcp6_hdr.th_sum, 0 - pkt->tcp6_hdr.th_win);
    pkt->tcp6_hdr.th_win = 0;

    /* clear TCP options */
    uint32_t len = pkt->tcp6_hdr.th_off * 4;
    for (uint32_t i = sizeof(struct tcphdr) / sizeof(uint16_t); i < len / sizeof(uint16_t); i++) {
        uint16_t* ptr = (uint16_t*) &pkt->tcp6_hdr + i;
        checksum_diff(&pkt->tcp6_hdr.th_sum, TCPOPT_NOP_16B - *ptr);
        *ptr = TCPOPT_NOP_16B;
    }

    /* send pkt */
    if (pkt_len != write(fd, &pkt->ipv6_hdr, pkt_len)) DIE();
}

static inline void reply_icmp6_unreachable(struct pkt* pkt, uint32_t pkt_len, int fd) {
    /* populate icmp time exceed header */
    memset(&pkt->ipv6_padding, 0, 48);
    pkt->ipv6_padding.ip6_flow = 0x60;
    pkt->ipv6_padding.ip6_plen = htons(56);
    pkt->ipv6_padding.ip6_nxt  = IPPROTO_ICMPV6;
    pkt->ipv6_padding.ip6_hlim = REPLY_TTL;

    /* copy over source addr as dest addr*/
    memcpy(&pkt->ipv6_padding.ip6_src, &pkt->ipv6_hdr.ip6_dst, IPV6_ADDR_LEN);
    memcpy(&pkt->ipv6_padding.ip6_dst, &pkt->ipv6_hdr.ip6_src, IPV6_ADDR_LEN);
    pkt->icmp_padding.type = ICMP6_DST_UNREACH;
    pkt->icmp_padding.code = ICMP6_DST_UNREACH_NOPORT;

    /* update checksum */
    pkt->icmp_padding.checksum = 0;
    pkt->icmp_padding.checksum = checksum_calc_ipv6_phdr(&pkt->ipv6_padding, &pkt->icmp_padding, 56);

    /* send pkt */
    pkt_len = 96;
    if (pkt_len != write(fd, &pkt->ipv6_padding, pkt_len)) DIE();
}

static inline void reply_icmp6_ttl_exceeded(struct pkt* pkt, uint32_t pkt_len, int fd, struct in6_addr* timeout_addr) {
    /* populate icmp time exceed header */
    memset(&pkt->ipv6_padding, 0, 48);
    pkt->ipv6_padding.ip6_flow = 0x60;
    pkt->ipv6_padding.ip6_plen = htons(56);
    pkt->ipv6_padding.ip6_nxt  = IPPROTO_ICMPV6;
    pkt->ipv6_padding.ip6_hlim = REPLY_TTL;

    /* copy over source addr as dest addr*/
    memcpy(&pkt->ipv6_padding.ip6_src, timeout_addr, IPV6_ADDR_LEN);
    memcpy(&pkt->ipv6_padding.ip6_dst, &pkt->ipv6_hdr.ip6_src, IPV6_ADDR_LEN);
    pkt->icmp_padding.type = ICMP6_TIME_EXCEEDED;
    pkt->icmp_padding.code = 0;

    /* update checksum */
    pkt->icmp_padding.checksum = 0;
    pkt->icmp_padding.checksum = checksum_calc_ipv6_phdr(&pkt->ipv6_padding, &pkt->icmp_padding, 56);

    /* send pkt */
    pkt_len = 96;
    if (pkt_len != write(fd, &pkt->ipv6_padding, pkt_len)) DIE();
}

static inline void handle_pkt(struct pkt* pkt, uint32_t pkt_len, int fd) {
    if (pkt->ipv4_hdr.version == 4 && pkt->ipv4_hdr.ihl == 5) {
        uint32_t base_addr = find_matching_ipv4_block(pkt);
        uint32_t timeout_addr;
        if (base_addr == 0) {
            /* No matching address found */
            return;
        }

        if (is_ipv4_ttl_exceeded(pkt, base_addr, &timeout_addr)) {
            reply_icmp_ttl_exceeded(pkt, pkt_len, fd, timeout_addr);
        } else if ((pkt->ipv4_hdr.protocol == IPPROTO_ICMP) && (pkt->icmp_hdr.type == ICMP_ECHO)) {
            reply_icmp_ping(pkt, pkt_len, fd);
        } else if (pkt->ipv4_hdr.protocol == IPPROTO_TCP) {
            reply_tcp_syn(pkt, pkt_len, fd);
        } else {
            reply_icmp_unreachable(pkt, pkt_len, fd);
        }
    } else if (((pkt->ipv6_hdr.ip6_flow & 0xf0) >> 4) == 6) {
        struct in6_addr base_addr, timeout_addr;
        if (!find_matching_ipv6_block(pkt, &base_addr)) {
            /* No matching address found */
            return;
        }

        if (is_ipv6_ttl_exceeded(pkt, &base_addr, &timeout_addr)) {
            reply_icmp6_ttl_exceeded(pkt, pkt_len, fd, &timeout_addr);
        } else if ((pkt->ipv6_hdr.ip6_nxt == IPPROTO_ICMPV6) && (pkt->icmp6_hdr.type == ICMP6_ECHO_REQUEST)) {
            reply_icmp6_ping(pkt, pkt_len, fd);
        } else if (pkt->ipv6_hdr.ip6_nxt == IPPROTO_TCP) {
            reply_tcp6_syn(pkt, pkt_len, fd);
        } else {
            reply_icmp6_unreachable(pkt, pkt_len, fd);
        }
    }
}

static __attribute__((noreturn)) void* loop(void* arg) {
    struct pollfd fds[] = { { .fd = *(int*) arg, .events = POLLIN } };

    uint8_t     pkt_buf[PKT_MAX_LEN];
    struct pkt* pkt = (struct pkt*) pkt_buf;
    uint32_t    pkt_len;

    while (0 <= poll(fds, 1, -1)) {
        pkt_len = read(fds[0].fd, &pkt->ipv4_hdr, PKT_MAX_LEN - (((uint8_t*) &pkt->ipv4_hdr) - ((uint8_t*) &pkt)));
        if (pkt_len <= 0) DIE();

        handle_pkt(pkt, pkt_len, fds[0].fd);
    }

    DIE();
}

int main(int argc, char* argv[]) {
    int cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpus <= 0) {
        cpus = 1;
    }

    int       fds[cpus];
    pthread_t thread;

    tun_create(cpus, fds);
    if_up();

    /* List of configured prefix blocks */
    ip_blks_len = argc - 1;
    ip_blks     = malloc(sizeof(struct ip_blk) * ip_blks_len);

    for (int i = 1; i < argc; i++) {
        ip_blks[i - 1].af = (NULL != strstr(argv[i], ":")) ? AF_INET6 : AF_INET;

        char* slash               = strstr(argv[i], "/");
        ip_blks[i - 1].prefix_len = (ip_blks[i - 1].af == AF_INET6) ? 128 : 32;
        if (NULL != slash) {
            slash[0]                  = '\0';
            ip_blks[i - 1].prefix_len = atoi(&slash[1]);
        }

        if (0 == inet_pton(ip_blks[i - 1].af, argv[i], ip_blks[i - 1].addr)) DIE();

        if (NULL != slash) {
            slash[0] = '/';
        }

        if_addr(ip_blks[i - 1].af, ip_blks[i - 1].addr, ip_blks[i - 1].prefix_len);
    }

    printf("Interface: %s\n", ifname);
    printf("Index: %d\n", if_get_index());
    printf("Threads: %d\n", cpus);

    for (uint32_t i = 1; i < cpus; i++) {
        if (0 != pthread_create(&thread, NULL, loop, &fds[i])) DIE();

        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(i, &cpuset);
        if (0 != pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset)) DIE();
    }

    do {
        thread = pthread_self();

        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(0, &cpuset);
        if (0 != pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset)) DIE();
    } while (0);

    loop(&fds[0]);

    /* Don't need to free anything, since OS will clean up after we exit */
    return 0;
}

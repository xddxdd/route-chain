#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <poll.h>
#include <stdlib.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>

#define DIE() { perror(__func__); abort(); }
#define PKT_MAX_LEN 2048
#define BUF_SIZE 256
#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 16
#define IPV6_INT32_SEGS (IPV6_ADDR_LEN / sizeof(uint32_t))

struct ip_blk {
    uint32_t af;
    uint32_t prefix_len;

    union {
        char addr[IPV6_ADDR_LEN];
        uint32_t addr_v4;
        uint32_t addr_v6[IPV6_INT32_SEGS];
    };
};

struct pkt {
    union {
        struct {
            char reserved[20];
            struct iphdr ipv4_padding;
        };
        struct ip6_hdr ipv6_padding;
    };
    struct icmphdr icmp_padding;
    union {
        struct {
            struct iphdr ipv4_hdr;
            struct icmphdr icmp_hdr;
        };
        struct {
            struct ip6_hdr ipv6_hdr;
            struct icmphdr icmp6_hdr;
        };
    };
};

static char ifname[IFNAMSIZ];
static struct ip_blk *ip_blks = NULL;
uint32_t ip_blks_len = 0;

static int tun_create() {
    struct ifreq ifr;
    int fd, ret;

    /* allocate tun device */
    if (0 > (fd = open("/dev/net/tun", O_RDWR))) DIE();

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (0 > (ret = ioctl(fd, TUNSETIFF, (void*) &ifr))) DIE();

    strncpy(ifname, ifr.ifr_name, IFNAMSIZ);
    return fd;
}

static void if_up() {
    struct ifreq ifr;
    int fd;

    if (0 > (fd = socket(AF_INET, SOCK_DGRAM, 0))) DIE();

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_flags = IFF_UP | IFF_RUNNING;

    if (0 > ioctl(fd, SIOCSIFFLAGS, (void*) &ifr)) DIE();

    close(fd);
}

static int if_get_index() {
    int fd;
    char buf[BUF_SIZE];
    int len;
    snprintf(buf, BUF_SIZE, "/sys/class/net/%s/ifindex", ifname);
    fd = open(buf, O_RDONLY);
    len = read(fd, buf, BUF_SIZE);
    buf[len] = '\0';
    close(fd);
    return atoi(buf);
}

static void if_addr(const uint8_t af, const char* addr, const uint32_t prefix_len) {
    struct {
        struct nlmsghdr  nh;
        struct ifaddrmsg msg;
        char             attrbuf[BUF_SIZE];
    } req;

    struct rtattr *rta;
    int fd;
    if (0 > (fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE))) DIE();

    /* https://stackoverflow.com/questions/14369043/add-and-remove-ip-addresses-to-an-interface-using-ioctl-or-netlink */
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nh.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST | NLM_F_ACK;
    req.nh.nlmsg_type = RTM_NEWADDR;
    req.msg.ifa_family = af;
    req.msg.ifa_prefixlen = prefix_len;
    req.msg.ifa_scope = 0;
    req.msg.ifa_index = if_get_index();
    rta = (struct rtattr *) (((char *) &req) + NLMSG_ALIGN(req.nh.nlmsg_len));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len = RTA_LENGTH(af == AF_INET6 ? IPV6_ADDR_LEN : IPV4_ADDR_LEN);
    req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_LENGTH(af == AF_INET6 ? IPV6_ADDR_LEN : IPV4_ADDR_LEN);
    memcpy(RTA_DATA(rta), addr, af == AF_INET6 ? IPV6_ADDR_LEN : IPV4_ADDR_LEN);

    if (0 > send(fd, &req, req.nh.nlmsg_len, 0)) DIE();

    close(fd);
}

static uint16_t checksum_reduce(uint32_t cksum) {
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum = 0xffff - cksum;
    return (0x0000 == cksum) ? 0xffff : cksum;
}

static uint16_t checksum_calc(const void* buf, const uint32_t size) {
    uint32_t cksum = 0;
    const uint16_t* b = buf;

    for (uint32_t i = 0; i < size / 2; i++) {
        cksum += b[i];
    }
    return checksum_reduce(cksum);
}

static uint16_t checksum_calc_ipv6_phdr(const struct ip6_hdr *ip6, const void* buf, const uint32_t size) {
    uint32_t cksum = 0;
    const uint16_t* b = buf;

    for (uint32_t i = 0; i < 8; i++) {
        cksum += ip6->ip6_src.__in6_u.__u6_addr16[i];
        cksum += ip6->ip6_dst.__in6_u.__u6_addr16[i];
    }
    cksum += ip6->ip6_ctlun.ip6_un1.ip6_un1_plen;
    cksum += ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt << 8;

    for (uint32_t i = 0; i < size / 2; i++) {
        cksum += b[i];
    }
    return checksum_reduce(cksum);
}

static void checksum_diff(uint16_t* field, const uint32_t diff) {
    uint32_t cksum = ((uint32_t) *field) - diff;
    cksum = (cksum >> 16) + (cksum & 0xffff);
    *field = (0x0000 == cksum) ? 0xffff : cksum;
}

static void loop(const int fd) {
    struct pollfd fds[] = {
        {.fd = fd, .events = POLLIN}
    };

    uint8_t pkt_buf[PKT_MAX_LEN];
    struct pkt *pkt = (struct pkt*) pkt_buf;
    uint32_t pkt_len;

    while (0 <= poll(fds, 1, -1)) {
        pkt_len = read(fd, &pkt->ipv4_hdr,
                       PKT_MAX_LEN - (((uint8_t*) &pkt->ipv4_hdr) - ((uint8_t*) &pkt)));
        if (pkt_len <= 0) DIE();

        if (pkt->ipv4_hdr.version == 4 && pkt->ipv4_hdr.ihl == 5) {
            /* Only packets without IP options is supported */
            if (
                (pkt->ipv4_hdr.protocol == IPPROTO_ICMP)
                && (pkt->icmp_hdr.type == ICMP_ECHO)
            ) {
                /* swap src/dst address */
                uint32_t tmp = pkt->ipv4_hdr.daddr;
                pkt->ipv4_hdr.daddr = pkt->ipv4_hdr.saddr;
                pkt->ipv4_hdr.saddr = tmp;

                /* set pkt type */
                pkt->icmp_hdr.type = ICMP_ECHOREPLY;
                /* update checksum */
                checksum_diff(&pkt->icmp_hdr.checksum, ICMP_ECHOREPLY - ICMP_ECHO);

                /* send pkt */
                if (pkt_len != write(fd, &pkt->ipv4_hdr, pkt_len)) DIE();
            } else {
                /* populate icmp time exceed header */
                memset(&pkt->ipv4_padding, 0, 28);
                pkt->ipv4_padding.version = 4;
                pkt->ipv4_padding.ihl = 5;
                pkt->ipv4_padding.tot_len = htons(56);
                pkt->ipv4_padding.ttl = 255;
                pkt->ipv4_padding.protocol = IPPROTO_ICMP;

                /* copy over source addr as dest addr*/
                pkt->ipv4_padding.daddr = pkt->ipv4_hdr.saddr;
                pkt->ipv4_padding.saddr = 0;
                /* find configured ip block, create response */
                for (uint32_t i = 0; i < ip_blks_len; i++) {
                    if (ip_blks[i].af != AF_INET) continue;

                    uint32_t masked_daddr = ntohl(pkt->ipv4_hdr.daddr) & (0xffffffff << (32 - ip_blks[i].prefix_len));
                    uint32_t masked_ipblk = ntohl(ip_blks[i].addr_v4) & (0xffffffff << (32 - ip_blks[i].prefix_len));
                    if (masked_daddr != masked_ipblk) continue;

                    pkt->ipv4_padding.saddr = htonl(ntohl(ip_blks[i].addr_v4) + pkt->ipv4_hdr.ttl);
                    break;
                }
                if (0 == pkt->ipv4_padding.saddr) {
                    /* No matching address found */
                    continue;
                }

                /* check if reached target, to end the traceroute */
                if (pkt->ipv4_padding.saddr == pkt->ipv4_hdr.daddr) {
                    pkt->icmp_padding.type = ICMP_DEST_UNREACH;
                    pkt->icmp_padding.code = ICMP_PORT_UNREACH;
                } else {
                    pkt->icmp_padding.type = ICMP_TIME_EXCEEDED;
                    pkt->icmp_padding.code = 0;
                }

                /* update checksum */
                pkt->ipv4_padding.check = 0;
                pkt->ipv4_padding.check = checksum_calc(&pkt->ipv4_padding, 20);
                pkt->icmp_padding.checksum = 0;
                pkt->icmp_padding.checksum = checksum_calc(&pkt->icmp_padding, 36);

                /* send pkt */
                pkt_len = 56;
                if (pkt_len != write(fd, &pkt->ipv4_padding, pkt_len)) DIE();
            }
        } else if(((pkt->ipv6_hdr.ip6_ctlun.ip6_un1.ip6_un1_flow & 0xf0) >> 4) == 6) {
            /* Only packets without IP options is supported */
            if (
                (pkt->ipv6_hdr.ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6)
                && (pkt->icmp6_hdr.type == ICMP6_ECHO_REQUEST)
            ) {
                /* swap src/dst address */
                char tmp[IPV6_ADDR_LEN];
                memcpy(tmp, &pkt->ipv6_hdr.ip6_dst, IPV6_ADDR_LEN);
                memcpy(&pkt->ipv6_hdr.ip6_dst, &pkt->ipv6_hdr.ip6_src, IPV6_ADDR_LEN);
                memcpy(&pkt->ipv6_hdr.ip6_src, tmp, IPV6_ADDR_LEN);

                /* set pkt type */
                pkt->icmp6_hdr.type = ICMP6_ECHO_REPLY;
                /* update checksum */
                checksum_diff(&pkt->icmp6_hdr.checksum, ICMP6_ECHO_REPLY - ICMP6_ECHO_REQUEST);

                /* send pkt */
                if (pkt_len != write(fd, &pkt->ipv4_hdr, pkt_len)) DIE();
            } else {
                const static uint32_t zero_addr_v6[IPV6_INT32_SEGS] = {0, 0, 0, 0};

                /* populate icmp time exceed header */
                memset(&pkt->ipv6_padding, 0, 48);
                pkt->ipv6_padding.ip6_ctlun.ip6_un1.ip6_un1_flow = 0x60;
                pkt->ipv6_padding.ip6_ctlun.ip6_un1.ip6_un1_plen = htons(56);
                pkt->ipv6_padding.ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_ICMPV6;
                pkt->ipv6_padding.ip6_ctlun.ip6_un1.ip6_un1_hlim = 255;

                /* copy over source addr as dest addr*/
                memcpy(&pkt->ipv6_padding.ip6_dst, &pkt->ipv6_hdr.ip6_src, IPV6_ADDR_LEN);
                memset(&pkt->ipv6_padding.ip6_src, 0, IPV6_ADDR_LEN);
                /* find configured ip block, create response */
                for (uint32_t i = 0; i < ip_blks_len; i++) {
                    if (ip_blks[i].af != AF_INET6) continue;

                    uint32_t masked_daddr;
                    uint32_t masked_ipblk;

                    if (ip_blks[i].prefix_len <= 32) {
                        masked_daddr = ntohl(pkt->ipv6_hdr.ip6_dst.__in6_u.__u6_addr32[0])
                                & (0xffffffff << (32 - ip_blks[i].prefix_len));
                        masked_ipblk = ntohl(ip_blks[i].addr_v6[0])
                                & (0xffffffff << (32 - ip_blks[i].prefix_len));
                        if (masked_daddr != masked_ipblk) continue;
                    } else {
                        masked_daddr = pkt->ipv6_hdr.ip6_dst.__in6_u.__u6_addr32[0];
                        masked_ipblk = ip_blks[i].addr_v6[0];
                        if (masked_daddr != masked_ipblk) continue;
                    }

                    if (ip_blks[i].prefix_len > 32) {
                        if (ip_blks[i].prefix_len <= 64) {
                            masked_daddr = ntohl(pkt->ipv6_hdr.ip6_dst.__in6_u.__u6_addr32[1])
                                    & (0xffffffff << (64 - ip_blks[i].prefix_len));
                            masked_ipblk = ntohl(ip_blks[i].addr_v6[1])
                                    & (0xffffffff << (64 - ip_blks[i].prefix_len));
                            if (masked_daddr != masked_ipblk) continue;
                        } else {
                            masked_daddr = pkt->ipv6_hdr.ip6_dst.__in6_u.__u6_addr32[1];
                            masked_ipblk = ip_blks[i].addr_v6[1];
                            if (masked_daddr != masked_ipblk) continue;
                        }
                    }

                    if (ip_blks[i].prefix_len > 64) {
                        if (ip_blks[i].prefix_len <= 96) {
                            masked_daddr = ntohl(pkt->ipv6_hdr.ip6_dst.__in6_u.__u6_addr32[2])
                                    & (0xffffffff << (96 - ip_blks[i].prefix_len));
                            masked_ipblk = ntohl(ip_blks[i].addr_v6[2])
                                    & (0xffffffff << (96 - ip_blks[i].prefix_len));
                            if (masked_daddr != masked_ipblk) continue;

                        } else {
                            masked_daddr = ntohl(pkt->ipv6_hdr.ip6_dst.__in6_u.__u6_addr32[2]);
                            masked_ipblk = ntohl(ip_blks[i].addr_v6[2]);
                            if (masked_daddr != masked_ipblk) continue;

                            masked_daddr = ntohl(pkt->ipv6_hdr.ip6_dst.__in6_u.__u6_addr32[3])
                                    & (0xffffffff << (128 - ip_blks[i].prefix_len));
                            masked_ipblk = ntohl(ip_blks[i].addr_v6[3])
                                    & (0xffffffff << (128 - ip_blks[i].prefix_len));
                            if (masked_daddr != masked_ipblk) continue;
                        }
                    }

                    /* Adding to higher digits is not implemented, but unlikely necessary anyway */
                    memcpy(&pkt->ipv6_padding.ip6_src, ip_blks[i].addr, IPV6_ADDR_LEN);
                    pkt->ipv6_padding.ip6_src.__in6_u.__u6_addr32[3]
                            = htonl(ntohl(pkt->ipv6_padding.ip6_src.__in6_u.__u6_addr32[3]) + pkt->ipv6_hdr.ip6_ctlun.ip6_un1.ip6_un1_hlim);
                    break;
                }
                if (0 == memcmp(zero_addr_v6, &pkt->ipv6_padding.ip6_src, IPV6_ADDR_LEN)) {
                    /* No matching address found */
                    continue;
                }

                /* check if reached target, to end the traceroute */
                if (0 == memcmp(&pkt->ipv6_hdr.ip6_dst, &pkt->ipv6_padding.ip6_src, IPV6_ADDR_LEN)) {
                    pkt->icmp_padding.type = ICMP6_DST_UNREACH;
                    pkt->icmp_padding.code = ICMP6_DST_UNREACH_NOPORT;
                } else {
                    pkt->icmp_padding.type = ICMP6_TIME_EXCEEDED;
                    pkt->icmp_padding.code = 0;
                }

                /* update checksum */
                pkt->icmp_padding.checksum = 0;
                pkt->icmp_padding.checksum = checksum_calc_ipv6_phdr(&pkt->ipv6_padding, &pkt->icmp_padding, 56);

                /* send pkt */
                pkt_len = 96;
                if (pkt_len != write(fd, &pkt->ipv6_padding, pkt_len)) DIE();
            }
        }
    }
}

int main(int argc, char* argv[]) {
    int fd = tun_create();
    if_up();

    /* List of configured prefix blocks */
    ip_blks_len = argc - 1;
    ip_blks = malloc(sizeof(struct ip_blk) * ip_blks_len);

    for (int i = 1; i < argc; i++) {
        ip_blks[i - 1].af = (NULL != strstr(argv[i], ":")) ? AF_INET6 : AF_INET;

        char* slash = strstr(argv[i], "/");
        ip_blks[i - 1].prefix_len = (ip_blks[i - 1].af == AF_INET6) ? 128 : 32;
        if (NULL != slash) {
            slash[0] = '\0';
            ip_blks[i - 1].prefix_len = atoi(&slash[1]);
        }

        if(0 == inet_pton(ip_blks[i - 1].af,
                          argv[i],
                          ip_blks[i - 1].addr)) DIE();

        if_addr(ip_blks[i - 1].af,
                ip_blks[i - 1].addr,
                ip_blks[i - 1].prefix_len);
    }

    printf("Interface: %s\n", ifname);
    printf("Index: %d\n", if_get_index());

    if (0 > fd) {
        return fd;
    }
    loop(fd);

    /* Don't need to free anything, since OS will clean up after we exit */
    return 0;
}
#ifndef _BIRD_MSYS_SYSIO_H_
#define _BIRD_MSYS_SYSIO_H_

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#ifndef ICMP6_FILTER
#define ICMP6_FILTER 1
#endif

#ifndef SO_REUSEPORT
#define SO_REUSEPORT SO_REUSEADDR
#endif

#ifndef SA_LEN
#define SA_LEN(x) sizeof(sockaddr)
#endif

#ifndef INIT_MREQ4
#define INIT_MREQ4(maddr, ifa) \
  ((struct ip_mreq) { \
    .imr_multiaddr = ipa_to_in4(maddr), \
    .imr_interface = { .s_addr = htonl(ip4_to_u32(ifa->sysdep)) } })
#endif

static inline int
sk_setup_multicast4(sock *s UNUSED)
{
  return 0;
}

static inline int
sk_join_group4(sock *s, ip_addr maddr)
{
  struct ip_mreq mr = INIT_MREQ4(maddr, s->iface);
  if (setsockopt(s->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
    ERR("IP_ADD_MEMBERSHIP");
  return 0;
}

static inline int
sk_leave_group4(sock *s, ip_addr maddr)
{
  struct ip_mreq mr = INIT_MREQ4(maddr, s->iface);
  if (setsockopt(s->fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mr, sizeof(mr)) < 0)
    ERR("IP_DROP_MEMBERSHIP");
  return 0;
}

#define CMSG4_SPACE_PKTINFO CMSG_SPACE(sizeof(struct in_pktinfo))
#define CMSG4_SPACE_TTL CMSG_SPACE(sizeof(int))

static inline int
sk_request_cmsg4_pktinfo(sock *s)
{
  int enable = 1;
  if (setsockopt(s->fd, SOL_IP, IP_PKTINFO, &enable, sizeof(enable)) < 0)
    ERR("IP_PKTINFO");
  return 0;
}

static inline int
sk_request_cmsg4_ttl(sock *s)
{
  int enable = 1;
  if (setsockopt(s->fd, SOL_IP, IP_RECVTTL, &enable, sizeof(enable)) < 0)
    ERR("IP_RECVTTL");
  return 0;
}

static inline void
sk_process_cmsg4_pktinfo(sock *s, struct cmsghdr *cm)
{
  if ((cm->cmsg_type == IP_PKTINFO) &&
      (cm->cmsg_len >= CMSG_LEN(sizeof(struct in_pktinfo))))
  {
    const struct in_pktinfo *pi = (const void *) CMSG_DATA(cm);
    s->laddr = ipa_from_in4(pi->ipi_addr);
    s->lifindex = pi->ipi_ifindex;
  }
}

static inline void
sk_process_cmsg4_ttl(sock *s, struct cmsghdr *cm)
{
  if ((cm->cmsg_type == IP_TTL) && (cm->cmsg_len >= CMSG_LEN(sizeof(int))))
    s->rcv_ttl = *(const int *) CMSG_DATA(cm);
}
static inline void sk_prepare_cmsgs4(sock *s UNUSED, struct msghdr *msg UNUSED, void *cbuf UNUSED, size_t cbuflen UNUSED) { }
static inline void sk_prepare_ip_header(sock *s UNUSED, void *hdr UNUSED, int dlen UNUSED) { }
/* TCP TTL security cannot be enforced by the Windows socket API. Allow the
 * session to run, but never silently claim that receive-side GTSM is active. */
static inline int sk_set_min_ttl4(sock *s UNUSED, int ttl UNUSED)
{
  static int warned;
  if (!warned)
  {
    warned = 1;
    log(L_WARN "Socket: Windows cannot enforce the minimum received IPv4 TTL; BGP TTL security is transmit-only");
  }
  return 0;
}

static inline int sk_set_min_ttl6(sock *s UNUSED, int ttl UNUSED)
{
  static int warned;
  if (!warned)
  {
    warned = 1;
    log(L_WARN "Socket: Windows cannot enforce the minimum received IPv6 hop limit; BGP TTL security is transmit-only");
  }
  return 0;
}
static inline int sk_disable_mtu_disc4(sock *s UNUSED) { return 0; }
static inline int sk_disable_mtu_disc6(sock *s UNUSED) { return 0; }
static inline int sk_set_priority(sock *s UNUSED, int prio UNUSED) { return 0; }
static inline int sk_set_freebind(sock *s UNUSED) { return 0; }
static inline int sk_set_udp6_no_csum_rx(sock *s UNUSED) { return 0; }

int sk_set_md5_auth(sock *s UNUSED, ip_addr local UNUSED, ip_addr remote UNUSED, int pxlen UNUSED, struct iface *ifa UNUSED, const char *passwd UNUSED, int setkey UNUSED)
{
  ERR_MSG("TCP MD5 authentication is not supported");
}

#endif

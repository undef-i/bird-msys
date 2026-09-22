#include <string.h>

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "lib/socket.h"
#include "lib/resource.h"
#include "sysdep/unix/unix.h"
#include "sysdep/unix/krt.h"
#include "sysdep/msys/winapi.h"

const int rt_default_ecmp = 0;
int sk_priority_control;

int
krt_sys_get_attr(const eattr *a UNUSED, byte *buf UNUSED, int buflen UNUSED)
{
  if (a->id == EA_KRT_PREFSRC)
  {
    bsprintf(buf, "prefsrc");
    return GA_NAME;
  }
  return GA_UNKNOWN;
}

int sk_get_ao_info(sock *s UNUSED, struct ao_info *val UNUSED) { return -1; }
int sk_get_active_ao_keys(sock *s UNUSED, int *current_key UNUSED, int *rnext_key UNUSED) { return -1; }
bool tcp_ao_alg_known(int algorithm UNUSED) { return false; }
int sk_add_ao_key(sock *s UNUSED, ip_addr prefix UNUSED, int pxlen UNUSED, struct iface *ifa UNUSED, const struct ao_key *key UNUSED, bool current UNUSED, bool rnext UNUSED) { return -1; }
int sk_delete_ao_key(sock *s UNUSED, ip_addr prefix UNUSED, int pxlen UNUSED, struct iface *ifa UNUSED, const struct ao_key *key UNUSED, const struct ao_key *current UNUSED, const struct ao_key *rnext UNUSED) { return -1; }
int sk_set_rnext_ao_key(sock *s UNUSED, const struct ao_key *key UNUSED) { return -1; }
int sk_check_ao_keys(sock *s UNUSED, const struct ao_key **keys UNUSED, int num UNUSED, const char *name UNUSED) { return -1; }
void sk_dump_ao_info(sock *s UNUSED, struct dump_request *dreq UNUSED) { }
void sk_dump_ao_keys(sock *s UNUSED, struct dump_request *dreq UNUSED) { }

static linpool *msys_lp;
static list msys_krt_list;

#define MSYS_IFACE_MAP_MAX 256
struct msys_iface_map_entry {
  unsigned index;
  struct iface *iface;
};
static struct msys_iface_map_entry msys_iface_map[MSYS_IFACE_MAP_MAX];
static unsigned msys_iface_map_count;

struct msys_onlink_entry {
  unsigned index;
  ip4_addr prefix;
  uint pxlen;
};
static struct msys_onlink_entry msys_onlink_map[MSYS_IFACE_MAP_MAX];
static unsigned msys_onlink_map_count;

static struct iface *msys_route_iface(const struct msys_win_route *wr);
static void msys_onlink_route_cb(const struct msys_win_route *wr, void *data);

int
krt_is_onlink(struct iface *iface, ip_addr addr)
{
  if (!iface || !ipa_is_ip4(addr))
    return 0;

  int result = msys_win_is_onlink(iface->index, ipa_to_u32(addr));
  if (result >= 0)
    return result;

  ip4_addr ip = ipa_to_ip4(addr);
  for (unsigned i = 0; i < msys_onlink_map_count; i++)
    if ((msys_onlink_map[i].index == iface->index) &&
        ip4_equal(ip4_and(ip, ip4_mkmask(msys_onlink_map[i].pxlen)),
                  msys_onlink_map[i].prefix))
      return 1;
  return 0;
}

static void
msys_iface_name(char *name, unsigned index)
{
  const unsigned max = sizeof(((struct iface *) 0)->name) - 1;
  size_t length = strlen(name);

  if (length <= max)
    return;

  char suffix[12];
  int suffix_len = bsprintf(suffix, "#%u", index);
  if ((suffix_len < 0) || ((unsigned) suffix_len >= max))
  {
    bsprintf(name, "if%u", index);
    return;
  }

  name[max - suffix_len] = 0;
  memcpy(name + max - suffix_len, suffix, suffix_len + 1);
}

void
krt_sys_io_init(void)
{
  msys_lp = lp_new(krt_pool);
  init_list(&msys_krt_list);
}

void
krt_sys_init(struct krt_proto *p)
{
  add_tail(&msys_krt_list, &p->sys.n);
}

void
krt_sys_shutdown(struct krt_proto *p)
{
  rem_node(&p->sys.n);
}

static void
msys_iface_cb(const struct msys_win_iface *wi, void *data UNUSED)
{
  struct iface f = {};
  struct iface *iface;

  if (!wi->index)
    return;

  strncpy(f.name, wi->name, sizeof(f.name) - 1);
  f.index = wi->index;
  msys_iface_name(f.name, f.index);
  f.mtu = wi->mtu;
  f.flags = IF_ADMIN_UP;
  if (wi->up) f.flags |= IF_LINK_UP;
  if (wi->loopback)
    f.flags |= IF_MULTIACCESS | IF_LOOPBACK | IF_IGNORE;
  else if (wi->point_to_point) f.flags |= IF_MULTICAST;
  else f.flags |= IF_MULTIACCESS | (wi->broadcast ? IF_BROADCAST : 0);
  if (wi->multicast) f.flags |= IF_MULTICAST;
  if (wi->mac_len == sizeof(f.lladdr))
    memcpy(&f.lladdr, wi->mac, sizeof(f.lladdr));

  iface = if_update(&f);
  if ((wi->ipv6_index != 0) && (wi->ipv6_index != wi->index) &&
      (msys_iface_map_count < MSYS_IFACE_MAP_MAX))
    msys_iface_map[msys_iface_map_count++] = (struct msys_iface_map_entry) {
      .index = wi->ipv6_index,
      .iface = iface,
    };
  for (size_t n = 0; n < wi->addr_count; n++)
  {
    const struct msys_win_addr *wa = &wi->addrs[n];
    struct ifa ifa = {};
    int scope;

    ifa.iface = iface;
    ifa.ip = (wa->family == AF_INET) ? ipa_from_ip4(get_ip4(wa->address)) :
      ipa_from_ip6(get_ip6(wa->address));

    if (wa->family == AF_INET)
    {
      net_fill_ip4(&ifa.prefix, ipa_to_ip4(ifa.ip), wa->prefix_len);
      net_normalize(&ifa.prefix);
      if ((iface->flags & IF_BROADCAST) && wa->prefix_len < 31)
        ifa.brd = ipa_from_ip4(ip4_or(ipa_to_ip4(ifa.ip),
                                      ip4_not(ip4_mkmask(wa->prefix_len))));
      if (wa->prefix_len == 31)
        ifa.opposite = ipa_opposite_m1(ifa.ip);
      if (wa->prefix_len == 32)
        ifa.flags |= IA_HOST;
      if (!ip4_nonzero(iface->sysdep))
        iface->sysdep = ipa_to_ip4(ifa.ip);
    }
    else
    {
      net_fill_ip6(&ifa.prefix, ipa_to_ip6(ifa.ip), wa->prefix_len);
      net_normalize(&ifa.prefix);
      if (wa->prefix_len == 128)
        ifa.flags |= IA_HOST;
    }

    scope = ipa_classify(ifa.ip);
    if (scope >= 0)
    {
      ifa.scope = scope & IADDR_SCOPE_MASK;
      ifa_update(&ifa);
    }
  }
}

void
kif_do_scan(struct kif_proto *p UNUSED)
{
  msys_iface_map_count = 0;
  msys_onlink_map_count = 0;
  if_start_update();
  int error = msys_win_scan_ifaces(msys_iface_cb, NULL);
  if (error)
  {
    log(L_ERR "KIF: Windows interface scan failed: %d", error);
    return;
  }
  error = msys_win_scan_routes(msys_onlink_route_cb, NULL);
  if (error)
  {
    log(L_ERR "KIF: Windows onlink route scan failed: %d (%s)", error,
        msys_win_error_text(error));
    return;
  }
  if_end_update();
}

int
kif_update_sysdep_addr(struct iface *i UNUSED)
{
  return 0;
}

static struct iface *
msys_route_iface(const struct msys_win_route *wr)
{
  struct iface *iface = if_find_by_index(wr->interface_index);
  if (iface)
    return iface;

  for (unsigned i = 0; i < msys_iface_map_count; i++)
    if (msys_iface_map[i].index == wr->interface_index)
      return msys_iface_map[i].iface;

  return NULL;
}

static void
msys_onlink_route_cb(const struct msys_win_route *wr, void *data UNUSED)
{
  if (wr->family != AF_INET)
    return;
  if (ipa_nonzero(ipa_from_ip4(get_ip4(wr->gateway))))
    return;
  if (wr->prefix_len > IP4_MAX_PREFIX_LENGTH)
    return;
  if (msys_onlink_map_count >= MSYS_IFACE_MAP_MAX)
    return;
  msys_onlink_map[msys_onlink_map_count++] = (struct msys_onlink_entry) {
    .index = wr->interface_index,
    .prefix = ip4_and(get_ip4(wr->destination), ip4_mkmask(wr->prefix_len)),
    .pxlen = wr->prefix_len,
  };
}

static void
msys_route_one(const struct msys_win_route *wr, struct krt_proto *p)
{
  struct iface *iface;
  net_addr dst;
  rta *ra;
  rte *e;
  ea_list *ea;
  int src;

  if ((wr->family == AF_INET && p->p.net_type != NET_IP4) ||
      (wr->family == AF_INET6 && p->p.net_type != NET_IP6))
    return;
  iface = msys_route_iface(wr);
  if (!iface || wr->prefix_len > ((wr->family == AF_INET) ? 32 : 128))
    return;

  if (wr->family == AF_INET)
    net_fill_ip4(&dst, get_ip4(wr->destination), wr->prefix_len);
  else
    net_fill_ip6(&dst, get_ip6(wr->destination), wr->prefix_len);
  net_normalize(&dst);

  ra = lp_allocz(msys_lp, RTA_MAX_SIZE);
  ra->source = RTS_INHERIT;
  ra->scope = SCOPE_UNIVERSE;
  ra->dest = RTD_UNICAST;
  ra->nh.iface = iface;
  ra->nh.gw = (wr->family == AF_INET) ? ipa_from_ip4(get_ip4(wr->gateway)) :
    ipa_from_ip6(get_ip6(wr->gateway));

  if (wr->protocol == MSYS_WIN_PROTO_ICMP) src = KRT_SRC_REDIRECT;
  else if (wr->protocol == MSYS_WIN_PROTO_LOCAL) src = KRT_SRC_KERNEL;
  else if ((wr->protocol == MSYS_WIN_PROTO_NETMGMT) &&
           (wr->metric == KRT_CF->sys.metric))
    src = KRT_SRC_BIRD;
  else src = KRT_SRC_ALIEN;

  ea = lp_alloc(msys_lp, sizeof(ea_list) + 2 * sizeof(eattr));
  *ea = (ea_list) { .flags = EALF_SORTED, .count = 2, .next = ra->eattrs };
  ra->eattrs = ea;
  ea->attrs[0] = (eattr) { .id = EA_KRT_SOURCE, .type = EAF_TYPE_INT,
                           .u.data = src };
  ea->attrs[1] = (eattr) { .id = EA_KRT_METRIC, .type = EAF_TYPE_INT,
                           .u.data = wr->metric };

  e = rte_get_temp(ra, p->p.main_source);
  e->net = net_get(p->p.main_channel->table, &dst);
  krt_got_route(p, e, src);
  lp_flush(msys_lp);
}

static void
msys_route_cb(const struct msys_win_route *wr, void *data)
{
  if (data)
  {
    msys_route_one(wr, data);
    return;
  }

  struct krt_proto *p;
  node *n;
  WALK_LIST2(p, n, msys_krt_list, sys.n)
    msys_route_one(wr, p);
}

void
krt_do_scan(struct krt_proto *p)
{
  int error = msys_win_scan_routes(msys_route_cb, p);
  if (error)
    log(L_ERR "KRT: Windows route scan failed: %d (%s)", error,
        msys_win_error_text(error));
}

static void
msys_route_from_nh(struct msys_win_route *wr, net *n, rta *a,
                   struct nexthop *nh, u32 metric)
{
  const net_addr *dst = n->n.addr;
  ip_addr gw = nh->gw;
  wr->family = dst->type == NET_IP4 ? AF_INET : AF_INET6;
  wr->prefix_len = dst->pxlen;
  wr->interface_index = nh->iface->index;
  wr->metric = metric;
  wr->protocol = MSYS_WIN_PROTO_NETMGMT;
  eattr *ea = ea_find(a->eattrs, EA_KRT_PREFSRC);
  if (ea)
    log(L_WARN "KRT: prefsrc is not supported by the Windows route API");
  if (wr->family == AF_INET)
  {
    put_ip4(wr->destination, net4_prefix(dst));
    put_ip4(wr->gateway, ipa_to_ip4(gw));
  }
  else
  {
    put_ip6(wr->destination, net6_prefix(dst));
    put_ip6(wr->gateway, ipa_to_ip6(gw));
  }
}

void
krt_replace_rte(struct krt_proto *p, net *n, rte *new, rte *old)
{
  struct msys_win_route wr;
  int error = 0;
  u32 metric = KRT_CF->sys.metric;

  if (old)
  {
    eattr *ea = ea_find(old->attrs->eattrs, EA_KRT_METRIC);
    u32 old_metric = ea ? ea->u.data : metric;
    for (struct nexthop *nh = &old->attrs->nh; nh && !error; nh = nh->next)
    {
      msys_route_from_nh(&wr, n, old->attrs, nh, old_metric);
      error = msys_win_change_route(&wr, 0);
    }
  }
  if (!error && new)
  {
    for (struct nexthop *nh = &new->attrs->nh; nh && !error; nh = nh->next)
    {
      msys_route_from_nh(&wr, n, new->attrs, nh, metric);
      error = msys_win_change_route(&wr, 1);
    }
  }

  if (new)
  {
    if (error) bmap_clear(&p->sync_map, new->id);
    else bmap_set(&p->sync_map, new->id);
  }

  if (error)
    log(L_WARN "KRT: Windows route update failed: %d (%s)", error,
        msys_win_error_text(error));
}

int
krt_capable(rte *e)
{
  return e->attrs->dest == RTD_UNICAST;
}

#ifndef _BIRD_MSYS_WINAPI_H_
#define _BIRD_MSYS_WINAPI_H_

#include <stddef.h>

#define MSYS_WIN_PROTO_LOCAL 2
#define MSYS_WIN_PROTO_NETMGMT 3
#define MSYS_WIN_PROTO_ICMP 4


struct msys_win_addr {
  int family;
  unsigned char address[16];
  unsigned prefix_len;
};

struct msys_win_iface {
  unsigned index;
  unsigned ipv6_index;
  unsigned mtu;
  unsigned up;
  unsigned loopback;
  unsigned multicast;
  unsigned broadcast;
  unsigned point_to_point;
  unsigned char mac[6];
  size_t mac_len;
  char name[64];
  const struct msys_win_addr *addrs;
  size_t addr_count;
};

struct msys_win_route {
  int family;
  unsigned char destination[16];
  unsigned prefix_len;
  unsigned char gateway[16];
  unsigned interface_index;
  unsigned metric;
  unsigned protocol;
};

typedef void (*msys_win_iface_cb)(const struct msys_win_iface *, void *);
typedef void (*msys_win_route_cb)(const struct msys_win_route *, void *);

int msys_win_scan_ifaces(msys_win_iface_cb callback, void *data);
int msys_win_scan_routes(msys_win_route_cb callback, void *data);
int msys_win_change_route(const struct msys_win_route *, int add);
int msys_win_is_onlink(unsigned interface_index, unsigned address);
int msys_win_notify_start(void);
void msys_win_notify_stop(void);
int msys_win_notify_pending(void);
int msys_win_wake_fd(void);
const char *msys_win_error_text(unsigned error);

#endif

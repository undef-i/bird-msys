#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdatomic.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "sysdep/msys/winapi.h"

static HANDLE route_notification;
static HANDLE address_notification;
static HANDLE interface_notification;
static atomic_int notify_pending;

static HANDLE notify_event;
static pthread_t notify_thread;
static int notify_thread_started;
static int notify_pipe[2] = { -1, -1 };
static atomic_int notify_stop;

static void
msys_notify_signal(PVOID context)
{
  atomic_store(&notify_pending, 1);
  if (context)
    SetEvent((HANDLE) context);
}

static VOID CALLBACK
msys_route_changed(PVOID context, PMIB_IPFORWARD_ROW2 row,
                   MIB_NOTIFICATION_TYPE type)
{ (void) row; (void) type; msys_notify_signal(context); }

static VOID CALLBACK
msys_address_changed(PVOID context, PMIB_UNICASTIPADDRESS_ROW row,
                     MIB_NOTIFICATION_TYPE type)
{ (void) row; (void) type; msys_notify_signal(context); }

static VOID CALLBACK
msys_interface_changed(PVOID context, PMIB_IPINTERFACE_ROW row,
                       MIB_NOTIFICATION_TYPE type)
{ (void) row; (void) type; msys_notify_signal(context); }

static void *
msys_notify_loop(void *arg)
{
  (void) arg;
  while (!atomic_load_explicit(&notify_stop, memory_order_acquire))
  {
    if (WaitForSingleObject(notify_event, INFINITE) != WAIT_OBJECT_0)
      break;
    if (atomic_load_explicit(&notify_stop, memory_order_acquire))
      break;

    char byte = 0;
    ssize_t rv = write(notify_pipe[1], &byte, 1);
    (void) rv;
  }
  return NULL;
}

int
msys_win_notify_start(void)
{
  NETIO_STATUS error;
  int flags;

  atomic_store(&notify_pending, 0);
  atomic_store(&notify_stop, 0);
  error = ERROR_NOT_ENOUGH_MEMORY;

  if (pipe(notify_pipe) < 0)
    goto fail;

  flags = fcntl(notify_pipe[1], F_GETFL, 0);
  if (flags >= 0)
    fcntl(notify_pipe[1], F_SETFL, flags | O_NONBLOCK);

  notify_event = CreateEvent(NULL, FALSE, FALSE, NULL);
  if (!notify_event)
    goto fail;

  if (pthread_create(&notify_thread, NULL, msys_notify_loop, NULL) != 0)
    goto fail;
  notify_thread_started = 1;

  error = NotifyRouteChange2(AF_UNSPEC, msys_route_changed, notify_event, FALSE,
                             &route_notification);
  if (error != NO_ERROR)
    goto fail;
  error = NotifyUnicastIpAddressChange(AF_UNSPEC, msys_address_changed,
                                       notify_event, FALSE, &address_notification);
  if (error != NO_ERROR)
    goto fail;
  error = NotifyIpInterfaceChange(AF_UNSPEC, msys_interface_changed,
                                  notify_event, FALSE, &interface_notification);
  if (error != NO_ERROR)
    goto fail;
  return 0;

fail:
  msys_win_notify_stop();
  return (int) error;
}

void
msys_win_notify_stop(void)
{
  if (route_notification)
  {
    CancelMibChangeNotify2(route_notification);
    route_notification = NULL;
  }
  if (address_notification)
  {
    CancelMibChangeNotify2(address_notification);
    address_notification = NULL;
  }
  if (interface_notification)
  {
    CancelMibChangeNotify2(interface_notification);
    interface_notification = NULL;
  }

  if (notify_thread_started)
  {
    atomic_store(&notify_stop, 1);
    if (notify_event)
      SetEvent(notify_event);
    pthread_join(notify_thread, NULL);
    notify_thread_started = 0;
  }
  if (notify_event)
  {
    CloseHandle(notify_event);
    notify_event = NULL;
  }
  if (notify_pipe[0] >= 0)
  {
    close(notify_pipe[0]);
    notify_pipe[0] = -1;
  }
  if (notify_pipe[1] >= 0)
  {
    close(notify_pipe[1]);
    notify_pipe[1] = -1;
  }
}

int
msys_win_notify_pending(void)
{ return atomic_exchange(&notify_pending, 0); }

int
msys_win_wake_fd(void)
{
  if (notify_pipe[0] < 0)
    return -1;
  return dup(notify_pipe[0]);
}

static void
copy_sockaddr(const SOCKADDR *sa, unsigned char *address, int *family)
{
  if (sa->sa_family == AF_INET)
  {
    *family = AF_INET;
    memcpy(address, &((const SOCKADDR_IN *) sa)->sin_addr, 4);
  }
  else if (sa->sa_family == AF_INET6)
  {
    *family = AF_INET6;
    memcpy(address, &((const SOCKADDR_IN6 *) sa)->sin6_addr, 16);
  }
  else
    *family = AF_UNSPEC;
}

int
msys_win_scan_ifaces(msys_win_iface_cb callback, void *data)
{
  ULONG size = 0;
  IP_ADAPTER_ADDRESSES *list, *aa;
  DWORD error;

  error = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX,
                               NULL, NULL, &size);
  if (error != ERROR_BUFFER_OVERFLOW)
    return (int) error;

  list = malloc(size);
  if (!list)
    return ERROR_NOT_ENOUGH_MEMORY;

  for (;;)
  {
    error = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX,
                                 NULL, list, &size);
    if (error != ERROR_BUFFER_OVERFLOW)
      break;
    free(list);
    list = malloc(size);
    if (!list)
      return ERROR_NOT_ENOUGH_MEMORY;
  }
  if (error != NO_ERROR)
  {
    free(list);
    return (int) error;
  }

  for (aa = list; aa; aa = aa->Next)
  {
    struct msys_win_iface iface = {};
    struct msys_win_addr *addresses = NULL;
    IP_ADAPTER_UNICAST_ADDRESS *ua;
    size_t count = 0, i = 0;

    for (ua = aa->FirstUnicastAddress; ua; ua = ua->Next)
      if ((ua->Address.lpSockaddr->sa_family == AF_INET) ||
          (ua->Address.lpSockaddr->sa_family == AF_INET6))
        count++;

    if (count)
      addresses = calloc(count, sizeof(*addresses));
    if (count && !addresses)
    {
      free(list);
      return ERROR_NOT_ENOUGH_MEMORY;
    }

    iface.index = aa->IfIndex ?: aa->Ipv6IfIndex;
    iface.ipv6_index = aa->Ipv6IfIndex;
    iface.mtu = aa->Mtu;
    iface.up = aa->OperStatus == IfOperStatusUp;
    iface.loopback = aa->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
    iface.point_to_point = (aa->IfType == IF_TYPE_PPP) ||
      (aa->IfType == IF_TYPE_TUNNEL) || (aa->IfType == IF_TYPE_SLIP);
    iface.multicast = !(aa->Flags & IP_ADAPTER_NO_MULTICAST);
    iface.broadcast = !iface.loopback && !iface.point_to_point;
    iface.mac_len = aa->PhysicalAddressLength < sizeof(iface.mac) ?
      aa->PhysicalAddressLength : sizeof(iface.mac);
    memcpy(iface.mac, aa->PhysicalAddress, iface.mac_len);

    if (aa->FriendlyName)
      WideCharToMultiByte(CP_UTF8, 0, aa->FriendlyName, -1,
                          iface.name, sizeof(iface.name), NULL, NULL);
    if (!iface.name[0] && aa->AdapterName)
      strncpy(iface.name, aa->AdapterName, sizeof(iface.name) - 1);
    iface.name[sizeof(iface.name) - 1] = 0;

    for (ua = aa->FirstUnicastAddress; ua; ua = ua->Next)
    {
      int family;
      if ((ua->Address.lpSockaddr->sa_family != AF_INET) &&
          (ua->Address.lpSockaddr->sa_family != AF_INET6))
        continue;
      if ((ua->Address.lpSockaddr->sa_family == AF_INET6) &&
          ((ua->DadState == IpDadStateDuplicate) ||
           (ua->DadState == IpDadStateInvalid)))
        continue;

      copy_sockaddr(ua->Address.lpSockaddr, addresses[i].address, &family);
      if (iface.loopback && (family == AF_INET) &&
          (addresses[i].address[0] != 127))
        iface.loopback = 0;
      if (iface.loopback && (family == AF_INET6))
      {
        int loopback6 = 1;
        for (int j = 0; j < 15; j++)
          if (addresses[i].address[j]) loopback6 = 0;
        if (!loopback6 || (addresses[i].address[15] != 1))
          iface.loopback = 0;
      }
      addresses[i].family = family;
      addresses[i].prefix_len = ua->OnLinkPrefixLength;
      i++;
    }

    iface.addrs = addresses;
    iface.addr_count = i;
    callback(&iface, data);
    free(addresses);
  }

  free(list);
  return 0;
}

int
msys_win_scan_routes(msys_win_route_cb callback, void *data)
{
  MIB_IPFORWARD_TABLE2 *table = NULL;
  DWORD error = GetIpForwardTable2(AF_UNSPEC, &table);

  if (error != NO_ERROR)
    return (int) error;

  for (ULONG i = 0; i < table->NumEntries; i++)
  {
    MIB_IPFORWARD_ROW2 *row = &table->Table[i];
    struct msys_win_route route = {};
    route.family = row->DestinationPrefix.Prefix.si_family;
    route.prefix_len = row->DestinationPrefix.PrefixLength;
    route.interface_index = row->InterfaceIndex;
    route.metric = row->Metric;
    route.protocol = row->Protocol;

    if (route.family == AF_INET)
    {
      memcpy(route.destination, &row->DestinationPrefix.Prefix.Ipv4.sin_addr, 4);
      memcpy(route.gateway, &row->NextHop.Ipv4.sin_addr, 4);
    }
    else if (route.family == AF_INET6)
    {
      memcpy(route.destination, &row->DestinationPrefix.Prefix.Ipv6.sin6_addr, 16);
      memcpy(route.gateway, &row->NextHop.Ipv6.sin6_addr, 16);
    }
    else
      continue;

    callback(&route, data);
  }

  FreeMibTable(table);
  return 0;
}

int
msys_win_change_route(const struct msys_win_route *route, int add)
{
  MIB_IPFORWARD_ROW2 row;
  MIB_IF_ROW2 iface = {};
  DWORD error;

  iface.InterfaceIndex = route->interface_index;
  error = GetIfEntry2(&iface);
  if ((error != NO_ERROR) ||
      ((route->family == AF_INET6) && (iface.InterfaceIndex != route->interface_index)))
  {
    ULONG size = 0;
    IP_ADAPTER_ADDRESSES *list = NULL;
    IP_ADAPTER_ADDRESSES *aa;

    error = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &size);
    if (error != ERROR_BUFFER_OVERFLOW)
      return (int) error;

    list = malloc(size);
    if (!list)
      return ERROR_NOT_ENOUGH_MEMORY;

    error = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, list, &size);
    if (error != NO_ERROR)
    {
      free(list);
      return (int) error;
    }

    error = ERROR_NOT_FOUND;
    for (aa = list; aa; aa = aa->Next)
      if ((aa->IfIndex == route->interface_index) ||
          (aa->Ipv6IfIndex == route->interface_index))
      {
        iface.InterfaceLuid = aa->Luid;
        iface.InterfaceIndex = (route->family == AF_INET6) ?
          aa->Ipv6IfIndex : aa->IfIndex;
        error = NO_ERROR;
        break;
      }

    free(list);
  }
  if (error != NO_ERROR)
    return (int) error;

  InitializeIpForwardEntry(&row);
  row.InterfaceLuid = iface.InterfaceLuid;
  row.InterfaceIndex = iface.InterfaceIndex;
  row.DestinationPrefix.PrefixLength = route->prefix_len;
  row.NextHop.si_family = route->family;
  row.Metric = route->metric;
  row.Protocol = MIB_IPPROTO_NETMGMT;
  row.SitePrefixLength = route->prefix_len;

  if (route->family == AF_INET)
  {
    row.DestinationPrefix.Prefix.si_family = AF_INET;
    memcpy(&row.DestinationPrefix.Prefix.Ipv4.sin_addr, route->destination, 4);
    row.NextHop.Ipv4.sin_family = AF_INET;
    memcpy(&row.NextHop.Ipv4.sin_addr, route->gateway, 4);
  }
  else
  {
    row.DestinationPrefix.Prefix.si_family = AF_INET6;
    memcpy(&row.DestinationPrefix.Prefix.Ipv6.sin6_addr, route->destination, 16);
    row.NextHop.Ipv6.sin6_family = AF_INET6;
    row.NextHop.Ipv6.sin6_scope_id = route->interface_index;
    memcpy(&row.NextHop.Ipv6.sin6_addr, route->gateway, 16);
  }

  error = add ? CreateIpForwardEntry2(&row) : DeleteIpForwardEntry2(&row);
  if (add && (error == ERROR_OBJECT_ALREADY_EXISTS))
    error = SetIpForwardEntry2(&row);
  if (!add && error == ERROR_NOT_FOUND)
    return 0;
  return error == NO_ERROR ? 0 : (int) error;
}

int
msys_win_is_onlink(unsigned interface_index, unsigned address)
{
  MIB_IF_ROW2 ifrow = {};
  MIB_IPFORWARD_ROW2 best = {};
  SOCKADDR_INET destination = {};
  SOCKADDR_INET source = {};
  MIB_IPFORWARD_TABLE2 *table = NULL;
  DWORD error;
  int result = 0;
  int found = 0;
  unsigned best_prefix_len = 0;
  ULONG best_metric = ULONG_MAX;

  ifrow.InterfaceIndex = interface_index;
  if (GetIfEntry2(&ifrow) == NO_ERROR)
  {
    destination.Ipv4.sin_family = AF_INET;
    destination.Ipv4.sin_addr.s_addr = htonl(address);
    best.InterfaceLuid = ifrow.InterfaceLuid;
    best.InterfaceIndex = interface_index;
    error = GetBestRoute2(&ifrow.InterfaceLuid, interface_index, NULL,
                          &destination, 0, &best, &source);
    if (error == NO_ERROR)
      return (best.InterfaceIndex == interface_index) &&
        (best.NextHop.Ipv4.sin_addr.s_addr == 0);
  }

  error = GetIpForwardTable2(AF_INET, &table);
  if (error != NO_ERROR || !table)
  {
    if (table)
      FreeMibTable(table);
    return -1;
  }

  for (ULONG i = 0; i < table->NumEntries; i++)
  {
    MIB_IPFORWARD_ROW2 *row = &table->Table[i];
    unsigned prefix;
    unsigned mask;

    if ((row->DestinationPrefix.Prefix.si_family != AF_INET) ||
        (row->InterfaceIndex != interface_index) ||
        (row->DestinationPrefix.PrefixLength > 32))
      continue;

    prefix = ntohl(row->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr);
    mask = row->DestinationPrefix.PrefixLength ?
      (0xffffffffU << (32 - row->DestinationPrefix.PrefixLength)) : 0;
    if (((address & mask) == (prefix & mask)) &&
        (!found || (row->DestinationPrefix.PrefixLength > best_prefix_len) ||
         ((row->DestinationPrefix.PrefixLength == best_prefix_len) &&
          (row->Metric < best_metric))))
    {
      found = 1;
      best_prefix_len = row->DestinationPrefix.PrefixLength;
      best_metric = row->Metric;
      result = (row->NextHop.Ipv4.sin_addr.s_addr == 0);
    }
  }

  FreeMibTable(table);
  return result;
}

const char *
msys_win_error_text(unsigned error)
{
  static char text[256];
  DWORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
  DWORD len = FormatMessageA(flags, NULL, error, 0, text, sizeof(text), NULL);

  if (!len)
    return "unknown Windows error";

  while (len && ((text[len - 1] == '\r') || (text[len - 1] == '\n') ||
                 (text[len - 1] == ' ')))
    text[--len] = 0;
  return text;
}

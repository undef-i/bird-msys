#ifndef BIRD_MSYS_ICMP6_H
#define BIRD_MSYS_ICMP6_H

#include <stdint.h>

struct icmp6_filter
{
  uint32_t icmp6_filt[8];
};

#define ICMP6_FILTER_SETPASS(type, filterp) \
  ((filterp)->icmp6_filt[(type) >> 5] &= ~(UINT32_C(1) << ((type) & 31)))

#define ICMP6_FILTER_SETBLOCK(type, filterp) \
  ((filterp)->icmp6_filt[(type) >> 5] |= (UINT32_C(1) << ((type) & 31)))

#define ICMP6_FILTER_SETPASSALL(filterp) \
  do { for (unsigned _i = 0; _i < 8; _i++) (filterp)->icmp6_filt[_i] = 0; } while (0)

#define ICMP6_FILTER_SETBLOCKALL(filterp) \
  do { for (unsigned _i = 0; _i < 8; _i++) (filterp)->icmp6_filt[_i] = UINT32_MAX; } while (0)

#endif

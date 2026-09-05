#ifndef MIMIC_COMMON_CHECKSUM_H
#define MIMIC_COMMON_CHECKSUM_H

#ifdef MIMIC_BPF
// clang-format off
#include "bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "defs.h"
// clang-format on
#else
#include <arpa/inet.h>
#include <linux/types.h>
#include <stddef.h>
#endif

static inline __u32 u32_fold(__u32 num) { return (num & 0xffff) + (num >> 16); }
static inline __u16 csum_fold(__u32 csum) { return ~u32_fold(u32_fold(csum)); }

static inline __u32 calc_csum(void* data, size_t data_len) {
  __u64 result = 0;
  const __u8* p = (const __u8*)data;
  size_t n32 = data_len & ~(size_t)31;
  for (size_t i = 0; i < n32; i += 32) {
    __u64 w0, w1, w2, w3;
    __builtin_memcpy(&w0, p + i, 8);
    __builtin_memcpy(&w1, p + i + 8, 8);
    __builtin_memcpy(&w2, p + i + 16, 8);
    __builtin_memcpy(&w3, p + i + 24, 8);
    w0 = __builtin_bswap64(w0);
    w1 = __builtin_bswap64(w1);
    w2 = __builtin_bswap64(w2);
    w3 = __builtin_bswap64(w3);
    result += (__u32)w0; result += w0 >> 32;
    result += (__u32)w1; result += w1 >> 32;
    result += (__u32)w2; result += w2 >> 32;
    result += (__u32)w3; result += w3 >> 32;
  }
  size_t n = data_len & ~(size_t)7;
  for (size_t i = n32; i < n; i += 8) {
    __u64 w;
    __builtin_memcpy(&w, p + i, sizeof(w));
    w = __builtin_bswap64(w);
    result += (__u32)w;
    result += w >> 32;
  }
  size_t rem = data_len - n;
  if (rem & 4) {
    __u32 w4;
    __builtin_memcpy(&w4, p + n, sizeof(w4));
    result += __builtin_bswap32(w4);
    n += 4;
  }
  if (rem & 2) {
    result += ((__u32)p[n] << 8) | p[n + 1];
    n += 2;
  }
  if (rem & 1) result += (__u32)p[n] << 8;
  __u32 r = (__u32)(result & 0xffffffff) + (__u32)(result >> 32);
  return u32_fold(u32_fold(r));
}

#endif  // MIMIC_COMMON_CHECKSUM_H

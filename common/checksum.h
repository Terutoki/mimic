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
  // Sum 32-bit big-endian words instead of 16-bit: identical checksum residue
  // class (callers still apply the single final csum_fold), one load+bswap per
  // step. A 64-bit accumulator is required: MAX_PACKET_SIZE worth of full
  // 32-bit words overflows u32 before folding.
  __u64 result = 0;
  const __u8* p = (const __u8*)data;
  size_t n = data_len & ~(size_t)3;
  for (size_t i = 0; i < n; i += 4) {
    __u32 w;
    __builtin_memcpy(&w, p + i, sizeof(w));
    result += __builtin_bswap32(w);
  }
  switch (data_len & 3) {
    case 1: result += (__u32)p[n] << 8; break;
    case 2: result += ((__u32)p[n] << 8) | p[n + 1]; break;
    case 3:
      result += ((__u32)p[n] << 8) | p[n + 1];
      result += (__u32)p[n + 2] << 8;
      break;
    default: break;
  }
  __u32 r = (__u32)(result & 0xffffffff) + (__u32)(result >> 32);
  return u32_fold(u32_fold(r));
}

#endif  // MIMIC_COMMON_CHECKSUM_H

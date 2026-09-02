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
  size_t n = data_len & ~(size_t)7;
  for (size_t i = 0; i < n; i += 8) {
    __u64 w;
    __builtin_memcpy(&w, p + i, sizeof(w));
    w = __builtin_bswap64(w);
    // Add the two 32-bit limbs separately: a single u64 add of the combined
    // value lets the low limb's carry poison the high limb (off-by-one on the
    // checksum), which the fold below has no way to recover.
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

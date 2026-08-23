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
  __u32 result = 0;
  for (size_t i = 0; i < data_len / 2; i++) {
    result += ntohs(*((__u16*)data + i));
  }
  if (data_len % 2 == 1) {
    result += (__u16)((__u8*)data)[data_len - 1] << 8;
  }
  return result;
}

#endif  // MIMIC_COMMON_CHECKSUM_H

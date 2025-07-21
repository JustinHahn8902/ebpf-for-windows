// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_hash.h"

static inline uint64_t
_ebpf_rotl64(uint64_t x, uint32_t r)
{
    return (x << r) | (x >> (64 - r));
}

static inline uint64_t
_ebpf_fmix64(uint64_t k)
{
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53ULL;
    k ^= k >> 33;
    return k;
}

uint64_t
ebpf_hash(_In_reads_((length_in_bits + 7) / 8) const uint8_t* data, size_t length_in_bits, uint64_t seed)
{
    const uint64_t c1 = 0x87c37b91114253d5ULL;
    const uint64_t c2 = 0x4cf5ad432745937fULL;

    const uint64_t m = 5;
    const uint64_t n1 = 0x52dce729;
    const uint64_t n2 = 0x38495ab5;

    const uint32_t length_in_bytes = (uint32_t)(length_in_bits >> 3);
    const uint32_t remaining_bits = (uint32_t)(length_in_bits & 7);

    uint64_t h1 = seed;
    uint64_t h2 = seed;

    for (uint32_t index = 0; index + 15 < length_in_bytes; index += 16) {

        uint64_t k1 = *(const uint64_t*)(data + index);
        uint64_t k2 = *(const uint64_t*)(data + index + 8);

        k1 *= c1;
        k1 = _ebpf_rotl64(k1, 31);
        k1 *= c2;
        h1 ^= k1;
        h1 = _ebpf_rotl64(h1, 27);
        h1 += h2;
        h1 = h1 * m + n1;

        k2 *= c2;
        k2 = _ebpf_rotl64(k2, 33);
        k2 *= c1;
        h2 ^= k2;
        h2 = _ebpf_rotl64(h2, 31);
        h2 += h1;
        h2 = h2 * m + n2;
    }

    const uint8_t* tail = data + (length_in_bytes & ~15);
    uint64_t k1 = 0, k2 = 0;
    switch (length_in_bytes & 15u) {
    case 15:
        k2 ^= (uint64_t)tail[14] << 48;
    case 14:
        k2 ^= (uint64_t)tail[13] << 40;
    case 13:
        k2 ^= (uint64_t)tail[12] << 32;
    case 12:
        k2 ^= (uint64_t)tail[11] << 24;
    case 11:
        k2 ^= (uint64_t)tail[10] << 16;
    case 10:
        k2 ^= (uint64_t)tail[9] << 8;
    case 9:
        k2 ^= (uint64_t)tail[8] << 0;
        k2 *= c2;
        k2 = _ebpf_rotl64(k2, 33);
        k2 *= c1;
        h2 ^= k2;

    case 8:
        k1 ^= (uint64_t)tail[7] << 56;
    case 7:
        k1 ^= (uint64_t)tail[6] << 48;
    case 6:
        k1 ^= (uint64_t)tail[5] << 40;
    case 5:
        k1 ^= (uint64_t)tail[4] << 32;
    case 4:
        k1 ^= (uint64_t)tail[3] << 24;
    case 3:
        k1 ^= (uint64_t)tail[2] << 16;
    case 2:
        k1 ^= (uint64_t)tail[1] << 8;
    case 1:
        k1 ^= (uint64_t)tail[0] << 0;
        k1 *= c1;
        k1 = _ebpf_rotl64(k1, 31);
        k1 *= c2;
        h1 ^= k1;
    }

    if (remaining_bits) {
        uint8_t bits = tail[(length_in_bytes & 15u)];
        bits >>= (8 - remaining_bits);
        k1 = (uint64_t)bits;
        k1 *= c1;
        k1 = _ebpf_rotl64(k1, 31);
        k1 *= c2;
        h1 ^= k1;
    }

    h1 ^= length_in_bytes;
    h2 ^= length_in_bytes;

    h1 += h2;
    h2 += h1;

    h1 = _ebpf_fmix64(h1);
    h2 = _ebpf_fmix64(h2);

    h1 += h2;

    return h1;
}

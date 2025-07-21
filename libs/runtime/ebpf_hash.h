// Copyright (c) eBPF for Windows contributors
// SPDX-License-Identifier: MIT

#include "ebpf_platform.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * Ported from https://github.com/aappleby/smhasher
     * Quote from
     * https://github.com/aappleby/smhasher/blob/61a0530f28277f2e850bfc39600ce61d02b518de/src/MurmurHash3.cpp#L2
     * "MurmurHash3 was written by Austin Appleby, and is placed in the public domain."
     *
     * Murmur3 128-bit hash modified for 64-bit
     *
     * @param data           Pointer to the start of data to be hashed
     * @param length_in_bits Length of the data in bits (≡ 8 × bytes for ASCII names)
     * @param seed           Any 64‑bit seed (0 is fine; use a random value for anti‑DOS)
     * @return               64‑bit Murmur3 hash
     */
    uint64_t
    ebpf_hash(_In_reads_((length_in_bits + 7) / 8) const uint8_t* data, size_t length_in_bits, uint64_t seed);

#ifdef __cplusplus
}
#endif
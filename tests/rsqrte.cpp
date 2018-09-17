#include <catch.hpp>

#include <cstdint>
#include <cstdio>
#include <cstddef>

using u8 = std::uint8_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

extern "C" u32 rsqrt3(u32);
extern "C" u32 rsqrt5(u32);
extern "C" u32 rsqrt7(u32);
extern "C" u32 rsqrt9(u32);
extern "C" u32 rsqrtv(u32);

static u32 aarch64(u32 i)  {
    u64 a = i;

    // Convert to u.10 (with 8 significant bits), force to odd
    if (a < 256) {
        // [0.25, 0.5)
        a = a * 2 + 1;
    } else {
        // [0.5, 1.0)
        a = (a | 1) * 2;
    }

    // Calculate largest b which for which b < 1.0 / sqrt(a).
    // Start from b = 1.0 (in u.9) since b cannot be smaller.
    u64 b = 512;
    // u.10 * u.9 * u.9 -> u.28
    while (a * (b + 1) * (b + 1) < (1u << 28)) {
        b++;
    }

    // Round to nearest u0.8 (with implied set integer bit).
    return static_cast<u8>((b + 1) / 2);
}

TEST_CASE("A64: RSQRTE_TEST", "[a64]") {
    for (u32 i = 128; i < 512; i++) {
        u32 x = 0x1f000000;
        if (i < 256) {
            x |= (i & 127) << 16;
            x |= 0x00800000;
        } else {
            x |= (i & 255) << 15;
        }
        x |=  0x00008000;
        //x &= ~0x00008000;
        //x |=  0x00007000;

        u32 result1 = ((rsqrt3(x) + (0x8000 >> 1)) >> 15) & 0xFF;
        u32 result2 = aarch64(i);
        u32 result3 = (rsqrt5((u32(i) << 23) | 0x007FFFFF) >> 24);
        u32 result4 = (rsqrt7(x) >> 15) & 0xFF;
        u32 result5 = (rsqrt9(x) >> 15) & 0xFF;
        u32 resultv = (rsqrtv(x) >> 15) & 0xFF;

        printf("%03x %08x %08x %08x %08x %06x %06x %06x %06x %06x %02x %02x %03x %02x %02x %02x %s %s %s %s %s\n", i, x, rsqrt5(u32(i) << 22), rsqrt7(x), rsqrt3(x), (rsqrt3(x) << 1) & 0xFFFFFF, (rsqrt3(x) + (0x6000 >> 1)) & 0xFFFFFF, (rsqrt7(x) << 1) & 0xFFFFFF, (rsqrt9(x) << 1) & 0xFFFFFF, (rsqrtv(x) << 1) & 0xFFFFFF, result1, result2, result3, result4, result5, resultv, result1 != result2 ? "*" : " ", result2 != result3 ? "?" : " ", result2 != result4 ? "." : " ", result5 != result2 ? "!" : " ", resultv != result2 ? "v" : " ");
    }
}

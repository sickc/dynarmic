/* This file is part of the dynarmic project.
 * Copyright (c) 2018 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#pragma once

#include <algorithm>
#include <functional>
#include <set>
#include <vector>

#include "common/bit_util.h"
#include "common/common_types.h"
#include "frontend/decoder/decoder_detail.h"
#include "frontend/decoder/matcher.h"

namespace Dynarmic::A64 {

namespace detail {

constexpr size_t ToFastLookupIndex(u32 instruction) {
    return ((instruction >> 10) & 0x00F) | ((instruction >> 18) & 0xFF0);
}

} // namespace detail

template<typename Visitor>
using Matcher = Decoder::Matcher<Visitor, u32>;

template<typename Visitor>
std::vector<Matcher<Visitor>> GetDecodeTable() {
    std::vector<Matcher<Visitor>> table = {
#define INST(fn, name, bitstring) Decoder::detail::detail<Matcher<Visitor>>::GetMatcher(&Visitor::fn, name, bitstring),
#include "a64.inc"
#undef INST
    };

    std::stable_sort(table.begin(), table.end(), [](const auto& matcher1, const auto& matcher2) {
        // If a matcher has more bits in its mask it is more specific, so it should come first.
        return Common::BitCount(matcher1.GetMask()) > Common::BitCount(matcher2.GetMask());
    });

    // Exceptions to the above rule of thumb.
    const std::set<std::string> comes_first {
        "MOVI, MVNI, ORR, BIC (vector, immediate)",
        "FMOV (vector, immediate)",
        "Unallocated SIMD modified immediate",
    };

    std::stable_partition(table.begin(), table.end(), [&](const auto& matcher) {
        return comes_first.count(matcher.GetName()) > 0;
    });

    return table;
}

template<typename Visitor>
std::array<std::vector<Matcher<Visitor>>, 0x1000> GetFastDecodeTable() {
    static const auto table = GetDecodeTable<Visitor>();

    std::array<std::vector<Matcher<Visitor>>, 0x1000> fast_table{};
    fast_table.fill({});

    for (const auto& matcher : table) {
        const size_t mask = detail::ToFastLookupIndex(matcher.GetMask());
        const size_t expected = detail::ToFastLookupIndex(matcher.GetExpected());

        for (size_t i = 0; i < fast_table.size(); i++) {
            if ((i & mask) == expected) {
                fast_table[i].emplace_back(matcher);
            }
        }
    }

    return fast_table;
}

template<typename Visitor>
const Matcher<Visitor>* Decode(u32 instruction) {
    static const auto fast_table = GetFastDecodeTable<Visitor>();

    const auto matches_instruction = [instruction](const auto& matcher) { return matcher.Matches(instruction); };

    const auto& sub_table = fast_table[detail::ToFastLookupIndex(instruction)];
    const auto iter = std::find_if(sub_table.begin(), sub_table.end(), matches_instruction);
    return iter != sub_table.end() ? &*iter : nullptr;
}

} // namespace Dynarmic::A64

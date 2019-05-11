/* This file is part of the dynarmic project.
 * Copyright (c) 2016 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#pragma once

#include <algorithm>
#include <optional>
#include <vector>

#include <dynarmic/A32/arch_version.h>

#include "common/common_types.h"
#include "frontend/A32/matcher.h"
#include "frontend/decoder/decoder_detail.h"

namespace Dynarmic::A32 {

template <typename Visitor>
using Thumb32Matcher = Matcher<Visitor, u32>;

template<typename V>
std::optional<std::reference_wrapper<const Thumb32Matcher<V>>> DecodeThumb32(u32 instruction) {
    static const std::vector<Thumb32Matcher<V>> table = {

#define INST(fn, name, bitstring, ver) Decoder::detail::detail<Thumb32Matcher<V>>::GetMatcher(&V::fn, name, bitstring, ArchVersion::ver)
#include "thumb32.inc"
#undef INST

    };

    const auto matches_instruction = [instruction](const auto& matcher){ return matcher.Matches(instruction); };

    auto iter = std::find_if(table.begin(), table.end(), matches_instruction);
    return iter != table.end() ? std::optional<std::reference_wrapper<const Thumb32Matcher<V>>>(*iter) : std::nullopt;
}

} // namespace Dynarmic::A32

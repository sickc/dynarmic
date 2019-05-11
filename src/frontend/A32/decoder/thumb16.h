/* This file is part of the dynarmic project.
 * Copyright (c) 2016 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#pragma once

#include <algorithm>
#include <functional>
#include <optional>
#include <vector>

#include <dynarmic/A32/arch_version.h>

#include "common/common_types.h"
#include "frontend/A32/matcher.h"
#include "frontend/decoder/decoder_detail.h"

namespace Dynarmic::A32 {

template <typename Visitor>
using Thumb16Matcher = Matcher<Visitor, u16>;

template<typename V>
std::optional<std::reference_wrapper<const Thumb16Matcher<V>>> DecodeThumb16(u16 instruction) {
    static const std::vector<Thumb16Matcher<V>> table = {

#define INST(fn, name, bitstring, ver) Decoder::detail::detail<Thumb16Matcher<V>>::GetMatcher(&V::fn, name, bitstring, ArchVersion::ver)
#include "thumb16.inc"
#undef INST

    };

    const auto matches_instruction = [instruction](const auto& matcher){ return matcher.Matches(instruction); };

    auto iter = std::find_if(table.begin(), table.end(), matches_instruction);
    return iter != table.end() ? std::optional<std::reference_wrapper<const Thumb16Matcher<V>>>(*iter) : std::nullopt;
}

} // namespace Dynarmic::A32

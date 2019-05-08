/* This file is part of the dynarmic project.
 * Copyright (c) 2019 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#pragma once

#include "frontend/decoder/matcher.h"

namespace Dynarmic::A32 {

enum class ArchVersion;

template <typename Visitor, typename OpcodeType>
class Matcher : public Decoder::Matcher<Visitor, OpcodeType> {
public:
    using parent_type         = Decoder::Matcher<Visitor, OpcodeType>;
    using opcode_type         = typename parent_type::opcode_type;
    using visitor_type        = typename parent_type::visitor_type;
    using handler_return_type = typename parent_type::handler_return_type;
    using handler_function    = typename parent_type::handler_function;

    Matcher(const char* const name, opcode_type mask, opcode_type expected, handler_function func, ArchVersion min_arch_version)
        : parent_type(name, mask, expected, func), min_arch_version(min_arch_version) {}

    ArchVersion GetMinArchVersion() const {
        return min_arch_version;
    }

private:
    ArchVersion min_arch_version;
};

} // namespace Dynarmic::A32

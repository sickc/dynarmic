/* This file is part of the dynarmic project.
 * Copyright (c) 2017 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#include <cstring>

#include <boost/optional.hpp>

#include "backend_x64/parse_mov.h"
#include "common/assert.h"
#include "common/common_types.h"

namespace Dynarmic {
namespace BackendX64 {

boost::optional<X64MemoryMovInstruction> ParseX64MemoryMovInstruction(const u8* code) {
    // We're only interested in a small number of mov/movzx instructions:
    // * 0x66 is the only legacy prefix and only appears at most once.
    // * REX prefix may or may not appear.
    // * Only [sib] addressing is used.
    // * Both the base and index registers are required.
    // If any of the above are violated, this function returns boost::none.

    bool opsize_prefix = false;
    if (*code == 0x66) {
        opsize_prefix = true;
        code++;
    }

    bool rex_w = false;
    bool rex_r = false;
    bool rex_x = false;
    bool rex_b = false;
    if ((*code & 0xF0) == 0x40) {
        rex_w = (*code & 0b1000) != 0;
        rex_r = (*code & 0b0100) != 0;
        rex_x = (*code & 0b0010) != 0;
        rex_b = (*code & 0b0001) != 0;
        code++;
    }

    X64MemoryMovInstruction ret;

    // Supported instructions:
    // mov r/m8, r8
    // mov r/m16, r16
    // mov r/m32, r32
    // mov r/m64, r64
    // movzx r32, r/m8
    // movzx r32, r/m16
    // mov r32, r/m32
    // mov r64, r/m64
    switch (*code) {
    case 0x88:
        ret.is_write = true;
        ret.is_zero_extend = false;
        ret.bit_size = 8;
        break;
    case 0x89:
        ret.is_write = true;
        ret.is_zero_extend = false;
        ret.bit_size = opsize_prefix ? 16 : (!rex_w ? 32 : 64);
        break;
    case 0x8B:
        if (opsize_prefix) {
            // mov r16, r/m16 not supported
            return {};
        }
        ret.is_write = false;
        ret.is_zero_extend = false;
        ret.bit_size = !rex_w ? 32 : 64;
        break;
    case 0x0F:
        code++;
        switch (*code) {
        case 0xB6:
            ret.is_write = false;
            ret.is_zero_extend = true;
            ret.bit_size = 8;
            break;
        case 0xB7:
            ret.is_write = false;
            ret.is_zero_extend = true;
            ret.bit_size = 16;
            break;
        default:
            return {}; // Unsupported opcode
        }
        break;
    default:
        return {}; // Unsupported opcode
    }
    code++;

    const u8 modrm = *code;
    const u8 modrm_mod = (modrm & 0b11000000) >> 6;
    const u8 modrm_reg = (modrm & 0b00111000) >> 3;
    const u8 modrm_rm = (modrm & 0b00000111);
    code++;
    if (modrm_rm != 0b100 || modrm_mod == 0b11) {
        // Only [sib] addressing supported
        return {};
    }
    ret.reg = modrm_reg + (rex_r ? 8 : 0);

    const u8 sib = *code;
    const u8 sib_scale = (sib & 0b11000000) >> 6;
    const u8 sib_index = (sib & 0b00111000) >> 3;
    const u8 sib_base = (sib & 0b00000111);
    code++;
    ret.scale = 1 << sib_scale;
    if (modrm_mod == 0b00 && sib_base == 0b101) {
        // Base register is required
        return {};
    }
    if (!rex_x && sib_index == 0b100) {
        // Index register is required
        return {};
    }
    ret.index = sib_index + (rex_x ? 8 : 0);
    ret.base = sib_base + (rex_b ? 8 : 0);

    switch (modrm_mod) {
    case 0b00:
        // No displacement
        ret.displacement = 0;
        break;
    case 0b01: {
        s8 displacement;
        std::memcpy(&displacement, code, sizeof(s8));
        ret.displacement = displacement;
        code += 1;
        break;
    }
    case 0b10: {
        s32 displacement;
        std::memcpy(&displacement, code, sizeof(s32));
        ret.displacement = displacement;
        code += 4;
        break;
    }
    case 0b11:
    default:
        // This should never happen
        ASSERT_MSG(false, "Bug in x64 mov parser");
        return {};
    }

    ret.next_instruction = code;
    return ret;
}

} // namespace BackendX64
} // namespace Dynarmic

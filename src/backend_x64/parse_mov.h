/* This file is part of the dynarmic project.
 * Copyright (c) 2017 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#pragma once

#include <boost/optional.hpp>

#include "common/common_types.h"

namespace Dynarmic {
namespace BackendX64 {

/**
 * Represents an x64 mov or movzx instruction.
 * Is only capable of representing moves to and from memory.
 * write: mov{zx} [scale * index + base + displacement], reg
 * read:  mov{zx} reg, [scale * index + base + displacement]
 */
struct X64MemoryMovInstruction {
    bool is_write;
    bool is_zero_extend; ///< Is this a movzx or a plain mov?
    size_t bit_size; ///< Is the memory location {8, 16, 32, 64} bits wide?
    size_t scale;
    size_t index;
    size_t base;
    s32 displacement;
    size_t reg;

    const u8* next_instruction; ///< Pointer to the start of the next instruction.
};

/**
 * Parses a x64 mov or movzx instruction.
 * Is only capable of parsing a subset of all possible x64 instructions.
 * @param code Where the first byte of the instruction is located.
 */
boost::optional<X64MemoryMovInstruction> ParseX64MemoryMovInstruction(const u8* code);

} // namespace BackendX64
} // namespace Dynarmic

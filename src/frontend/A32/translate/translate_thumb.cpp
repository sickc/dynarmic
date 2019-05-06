/* This file is part of the dynarmic project.
 * Copyright (c) 2016 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#include <tuple>

#include <dynarmic/A32/config.h>

#include "common/assert.h"
#include "common/bit_util.h"
#include "frontend/imm.h"
#include "frontend/A32/decoder/thumb16.h"
#include "frontend/A32/decoder/thumb32.h"
#include "frontend/A32/ir_emitter.h"
#include "frontend/A32/location_descriptor.h"
#include "frontend/A32/translate/impl/translate_thumb.h"
#include "frontend/A32/translate/translate.h"
#include "frontend/A32/types.h"

namespace Dynarmic::A32 {
namespace {

enum class ThumbInstSize {
    Thumb16, Thumb32
};

bool IsThumb16(u16 first_part) {
    return (first_part & 0xF800) <= 0xE800;
}

std::tuple<u32, ThumbInstSize> ReadThumbInstruction(u32 arm_pc, MemoryReadCodeFuncType memory_read_code) {
    u32 first_part = memory_read_code(arm_pc & 0xFFFFFFFC);
    if ((arm_pc & 0x2) != 0) {
        first_part >>= 16;
    }
    first_part &= 0xFFFF;

    if (IsThumb16(static_cast<u16>(first_part))) {
        // 16-bit thumb instruction
        return std::make_tuple(first_part, ThumbInstSize::Thumb16);
    }

    // 32-bit thumb instruction
    // These always start with 0b11101, 0b11110 or 0b11111.

    u32 second_part = memory_read_code((arm_pc + 2) & 0xFFFFFFFC);
    if (((arm_pc + 2) & 0x2) != 0) {
        second_part >>= 16;
    }
    second_part &= 0xFFFF;

    return std::make_tuple(static_cast<u32>((first_part << 16) | second_part), ThumbInstSize::Thumb32);
}

} // local namespace

IR::Block TranslateThumb(LocationDescriptor descriptor, MemoryReadCodeFuncType memory_read_code, const TranslationOptions& options) {
    IR::Block block{descriptor};
    ThumbTranslatorVisitor visitor{block, descriptor, options};
    visitor.Translate(memory_read_code);
    return block;
}

bool TranslateSingleThumbInstruction(IR::Block& block, LocationDescriptor descriptor, u32 thumb_instruction) {
    ThumbTranslatorVisitor visitor{block, descriptor, {}};

    const bool is_thumb_16 = (thumb_instruction >> 16) == 0;
    bool should_continue = true;
    if (is_thumb_16) {
        ASSERT(IsThumb16(static_cast<u16>(thumb_instruction)));
        should_continue = visitor.StepWithThumb16Instruction(static_cast<u16>(thumb_instruction));
    } else {
        ASSERT(!IsThumb16(static_cast<u16>(thumb_instruction >> 16)));
        should_continue = visitor.StepWithThumb32Instruction(thumb_instruction);
    }

    block.CycleCount()++;
    block.SetEndLocation(visitor.AdvanceLocationDescriptor());

    return should_continue;
}

ThumbTranslatorVisitor::ThumbTranslatorVisitor(IR::Block& block, LocationDescriptor descriptor, const TranslationOptions& options) : CommonTranslatorVisitor(block, descriptor, options) {
    ASSERT_MSG(descriptor.TFlag(), "The processor must be in Thumb mode");
}

bool ThumbTranslatorVisitor::Step(MemoryReadCodeFuncType memory_read_code) {
    const u32 arm_pc = ir.current_location.PC();
    const auto [thumb_instruction, inst_size] = ReadThumbInstruction(arm_pc, memory_read_code);

    if (inst_size == ThumbInstSize::Thumb16) {
        return StepWithThumb16Instruction(static_cast<u16>(thumb_instruction));
    }
    return StepWithThumb32Instruction(thumb_instruction);
}

bool ThumbTranslatorVisitor::StepWithThumb16Instruction(u16 thumb16_instruction) {
    current_instruction_size = 2;

    if (const auto decoder = DecodeThumb16<ThumbTranslatorVisitor>(thumb16_instruction)) {
        return decoder->get().call(*this, thumb16_instruction);
    }

    return UndefinedInstruction();
}

bool ThumbTranslatorVisitor::StepWithThumb32Instruction(u32 thumb32_instruction) {
    current_instruction_size = 4;

    if (const auto decoder = DecodeThumb32<ThumbTranslatorVisitor>(thumb32_instruction)) {
        return decoder->get().call(*this, thumb32_instruction);
    }

    return UndefinedInstruction();
}

} // namepsace Dynarmic::A32

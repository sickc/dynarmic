/* This file is part of the dynarmic project.
 * Copyright (c) 2016 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#include <algorithm>

#include "common/assert.h"
#include "dynarmic/A32/config.h"
#include "frontend/A32/decoder/arm.h"
#include "frontend/A32/decoder/vfp.h"
#include "frontend/A32/location_descriptor.h"
#include "frontend/A32/translate/impl/translate_arm.h"
#include "frontend/A32/translate/translate.h"
#include "frontend/A32/types.h"
#include "frontend/ir/basic_block.h"

namespace Dynarmic::A32 {

IR::Block TranslateArm(LocationDescriptor descriptor, MemoryReadCodeFuncType memory_read_code, const TranslationOptions& options) {
    IR::Block block{descriptor};
    ArmTranslatorVisitor visitor{block, descriptor, options};
    visitor.Translate(memory_read_code);
    return block;
}

bool TranslateSingleArmInstruction(IR::Block& block, LocationDescriptor descriptor, u32 arm_instruction) {
    ArmTranslatorVisitor visitor{block, descriptor, {}};

    // TODO: Proper cond handling

    const bool should_continue = visitor.StepWithArmInstruction(arm_instruction);

    // TODO: Feedback resulting cond status to caller somehow.

    block.CycleCount()++;
    block.SetEndLocation(visitor.AdvanceLocationDescriptor());

    return should_continue;
}

ArmTranslatorVisitor::ArmTranslatorVisitor(IR::Block& block, LocationDescriptor descriptor, const TranslationOptions& options) : CommonTranslatorVisitor(block, descriptor, options) {
    ASSERT_MSG(!descriptor.TFlag(), "The processor must be in Arm mode");
}

bool ArmTranslatorVisitor::ConditionPassed(Cond cond) {
    if (cond == Cond::NV) {
        // NV conditional is obsolete
        cond_state = ConditionalState::Break;
        return UnpredictableInstruction();
    }
    return CommonTranslatorVisitor::ConditionPassed(cond);
}

bool ArmTranslatorVisitor::Step(MemoryReadCodeFuncType memory_read_code) {
    const u32 arm_instruction = memory_read_code(ir.current_location.PC());
    return StepWithArmInstruction(arm_instruction);
}

bool ArmTranslatorVisitor::StepWithArmInstruction(u32 arm_instruction) {
    current_instruction_size = 4;

    if (const auto vfp_decoder = DecodeVFP<ArmTranslatorVisitor>(arm_instruction)) {
        return vfp_decoder->get().call(*this, arm_instruction);
    }

    if (const auto decoder = DecodeArm<ArmTranslatorVisitor>(arm_instruction)) {
        return decoder->get().call(*this, arm_instruction);
    }

    return UndefinedInstruction();
}

IR::ResultAndCarry<IR::U32> ArmTranslatorVisitor::EmitImmShift(IR::U32 value, ShiftType type, Imm<5> imm5, IR::U1 carry_in) {
    u8 imm5_value = imm5.ZeroExtend<u8>();

    switch (type) {
    case ShiftType::LSL:
        return ir.LogicalShiftLeft(value, ir.Imm8(imm5_value), carry_in);
    case ShiftType::LSR:
        imm5_value = imm5_value ? imm5_value : 32;
        return ir.LogicalShiftRight(value, ir.Imm8(imm5_value), carry_in);
    case ShiftType::ASR:
        imm5_value = imm5_value ? imm5_value : 32;
        return ir.ArithmeticShiftRight(value, ir.Imm8(imm5_value), carry_in);
    case ShiftType::ROR:
        if (imm5_value) {
            return ir.RotateRight(value, ir.Imm8(imm5_value), carry_in);
        } else {
            return ir.RotateRightExtended(value, carry_in);
        }
    }

    UNREACHABLE();
    return {};
}

IR::ResultAndCarry<IR::U32> ArmTranslatorVisitor::EmitRegShift(IR::U32 value, ShiftType type, IR::U8 amount, IR::U1 carry_in) {
    switch (type) {
    case ShiftType::LSL:
        return ir.LogicalShiftLeft(value, amount, carry_in);
    case ShiftType::LSR:
        return ir.LogicalShiftRight(value, amount, carry_in);
    case ShiftType::ASR:
        return ir.ArithmeticShiftRight(value, amount, carry_in);
    case ShiftType::ROR:
        return ir.RotateRight(value, amount, carry_in);
    }
    UNREACHABLE();
    return {};
}

} // namespace Dynarmic::A32

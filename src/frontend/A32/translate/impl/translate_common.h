/* This file is part of the dynarmic project.
 * Copyright (c) 2016 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#pragma once

#include "frontend/A32/ir_emitter.h"
#include "frontend/A32/location_descriptor.h"
#include "frontend/A32/translate/translate.h"

namespace Dynarmic::A32 {

enum class Exception;

enum class ConditionalState {
    /// We haven't met any conditional instructions yet.
    None,
    /// Current instruction is a conditional. This marks the end of this basic block.
    Break,
    /// This basic block is made up solely of conditional instructions.
    Translating,
    /// This basic block is made up of conditional instructions followed by unconditional instructions.
    Trailing,
};

struct CommonTranslatorVisitor {
    CommonTranslatorVisitor(IR::Block& block, LocationDescriptor descriptor, const TranslationOptions& options);

    A32::IREmitter ir;
    TranslationOptions options;
    size_t current_instruction_size = 4;

    ConditionalState cond_state = ConditionalState::None;
    bool ConditionPassed(Cond cond);

    void Translate(MemoryReadCodeFuncType memory_read_code);
    virtual bool Step(MemoryReadCodeFuncType memory_read_code) = 0;

    A32::LocationDescriptor AdvanceLocationDescriptor() const {
        return ir.current_location
                 .AdvancePC(static_cast<s32>(current_instruction_size))
                 .AdvanceIT();
    }

    bool InterpretThisInstruction();
    bool UnpredictableInstruction();
    bool UndefinedInstruction();
    bool RaiseException(Exception exception);
};

} // namespace Dynarmic::A32

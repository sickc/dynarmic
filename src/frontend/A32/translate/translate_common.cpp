/* This file is part of the dynarmic project.
 * Copyright (c) 2016 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#include <dynarmic/A32/config.h>

#include "frontend/A32/translate/impl/translate_common.h"

namespace Dynarmic::A32 {

static bool CondCanContinue(ConditionalState cond_state, const A32::IREmitter& ir) {
    ASSERT_MSG(cond_state != ConditionalState::Break, "Should never happen.");

    if (cond_state == ConditionalState::None) {
        return true;
    }

    // TODO: This is more conservative than necessary.
    return std::all_of(ir.block.begin(), ir.block.end(), [](const IR::Inst& inst) { return !inst.WritesToCPSR(); });
}

CommonTranslatorVisitor::CommonTranslatorVisitor(IR::Block& block, LocationDescriptor descriptor, const TranslationOptions& options) : ir(block, descriptor, options.arch_version), options(options) {}

bool CommonTranslatorVisitor::ConditionPassed(Cond cond) {
    ASSERT_MSG(cond_state != ConditionalState::Break,
               "This should never happen. We requested a break but that wasn't honored.");

    if (cond_state == ConditionalState::Translating) {
        if (ir.block.ConditionFailedLocation() != ir.current_location || cond == Cond::AL || cond == Cond::NV) {
            cond_state = ConditionalState::Trailing;
        } else {
            if (cond == ir.block.GetCondition()) {
                ir.block.SetConditionFailedLocation(AdvanceLocationDescriptor());
                ir.block.ConditionFailedCycleCount()++;
                return true;
            }

            // cond has changed, abort
            cond_state = ConditionalState::Break;
            ir.SetTerm(IR::Term::LinkBlockFast{ir.current_location});
            return false;
        }
    }

    if (cond == Cond::AL || cond == Cond::NV) {
        // Everything is fine with the world
        return true;
    }

    // non-AL cond

    if (!ir.block.empty()) {
        // We've already emitted instructions. Quit for now, we'll make a new block here later.
        cond_state = ConditionalState::Break;
        ir.SetTerm(IR::Term::LinkBlockFast{ir.current_location});
        return false;
    }

    // We've not emitted instructions yet.
    // We'll emit one instruction, and set the block-entry conditional appropriately.

    cond_state = ConditionalState::Translating;
    ir.block.SetCondition(cond);
    ir.block.SetConditionFailedLocation(AdvanceLocationDescriptor());
    ir.block.ConditionFailedCycleCount() = 1;
    return true;
}

void CommonTranslatorVisitor::Translate(MemoryReadCodeFuncType memory_read_code) {
    bool should_continue = true;
    while (should_continue && CondCanContinue(cond_state, ir)) {
        should_continue = Step(memory_read_code);

        if (cond_state == ConditionalState::Break) {
            break;
        }

        ir.current_location = AdvanceLocationDescriptor();
        ir.block.CycleCount()++;
    }

    if (cond_state == ConditionalState::Translating || cond_state == ConditionalState::Trailing) {
        if (should_continue) {
            ir.SetTerm(IR::Term::LinkBlockFast{ir.current_location});
        }
    }

    ASSERT_MSG(ir.block.HasTerminal(), "Terminal has not been set");

    ir.block.SetEndLocation(ir.current_location);
}

bool CommonTranslatorVisitor::InterpretThisInstruction() {
    ir.SetTerm(IR::Term::Interpret(ir.current_location));
    return false;
}

bool CommonTranslatorVisitor::UnpredictableInstruction() {
    ir.ExceptionRaised(Exception::UnpredictableInstruction);
    ir.SetTerm(IR::Term::CheckHalt{IR::Term::ReturnToDispatch{}});
    return false;
}

bool CommonTranslatorVisitor::UndefinedInstruction() {
    ir.ExceptionRaised(Exception::UndefinedInstruction);
    ir.SetTerm(IR::Term::CheckHalt{IR::Term::ReturnToDispatch{}});
    return false;
}

bool CommonTranslatorVisitor::RaiseException(Exception exception) {
    const u32 next_pc = static_cast<u32>(ir.current_location.PC() + current_instruction_size);
    ir.BranchWritePC(ir.Imm32(next_pc));
    ir.ExceptionRaised(exception);
    ir.SetTerm(IR::Term::CheckHalt{IR::Term::ReturnToDispatch{}});
    return false;
}

} // namepsace Dynarmic::A32

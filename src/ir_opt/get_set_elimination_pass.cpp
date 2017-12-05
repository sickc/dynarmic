/* This file is part of the dynarmic project.
 * Copyright (c) 2016 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#include <array>
#include <map>

#include "common/assert.h"
#include "common/common_types.h"
#include "frontend/ir/basic_block.h"
#include "frontend/ir/value.h"
#include "ir_opt/passes.h"

namespace Dynarmic {
namespace Optimization {

static void ElimPass(IR::Block& block) {
    using Iterator = IR::Block::iterator;
    struct RegisterInfo {
        IR::Value register_value;
        bool set_instruction_present = false;
        Iterator last_set_instruction;
    };
    std::array<RegisterInfo, 15> reg_info;
    std::map<std::tuple<Arm::Reg, Arm::Reg>, RegisterInfo> pair_reg_info;
    std::array<RegisterInfo, 32> ext_reg_singles_info;
    std::array<RegisterInfo, 32> ext_reg_doubles_info;
    struct CpsrInfo {
        RegisterInfo n;
        RegisterInfo z;
        RegisterInfo c;
        RegisterInfo v;
        RegisterInfo ge;
    } cpsr_info;

    const auto invalidate_associated_pair_registers = [&](Arm::Reg reg) {
        for (auto iter = pair_reg_info.begin(); iter != pair_reg_info.end();) {
            if (std::get<0>(iter->first) == reg || std::get<1>(iter->first) == reg) {
                iter = pair_reg_info.erase(iter);
            } else {
                ++iter;
            }
        }
    };

    const auto do_set = [&block](RegisterInfo& info, IR::Value value, Iterator set_inst) {
        if (info.set_instruction_present) {
            info.last_set_instruction->Invalidate();
            block.Instructions().erase(info.last_set_instruction);
        }

        info.register_value = value;
        info.set_instruction_present = true;
        info.last_set_instruction = set_inst;
    };

    const auto do_get = [](RegisterInfo& info, Iterator get_inst) {
        if (info.register_value.IsEmpty()) {
            info.register_value = IR::Value(&*get_inst);
            return;
        }
        get_inst->ReplaceUsesWith(info.register_value);
    };

    for (auto inst = block.begin(); inst != block.end(); ++inst) {
        switch (inst->GetOpcode()) {
        case IR::Opcode::SetRegister: {
            Arm::Reg reg = inst->GetArg(0).GetRegRef();
            if (reg == Arm::Reg::PC)
                break;

            size_t reg_index = static_cast<size_t>(reg);
            do_set(reg_info[reg_index], inst->GetArg(1), inst);

            invalidate_associated_pair_registers(reg);
            break;
        }
        case IR::Opcode::GetRegister: {
            Arm::Reg reg = inst->GetArg(0).GetRegRef();
            ASSERT(reg != Arm::Reg::PC);
            size_t reg_index = static_cast<size_t>(reg);
            do_get(reg_info[reg_index], inst);

            invalidate_associated_pair_registers(reg);
            break;
        }
        case IR::Opcode::SetRegisterPair: {
            Arm::Reg reg0 = inst->GetArg(0).GetRegRef();
            Arm::Reg reg1 = inst->GetArg(1).GetRegRef();
            reg_info[static_cast<size_t>(reg0)] = {};
            reg_info[static_cast<size_t>(reg1)] = {};

            auto p = std::make_pair(reg0, reg1);
            if (pair_reg_info.count(p) == 0) {
                invalidate_associated_pair_registers(reg0);
                invalidate_associated_pair_registers(reg1);
            }
            do_set(pair_reg_info[p], inst->GetArg(2), inst);
            break;
        }
        case IR::Opcode::GetRegisterPair: {
            Arm::Reg reg0 = inst->GetArg(0).GetRegRef();
            Arm::Reg reg1 = inst->GetArg(1).GetRegRef();
            reg_info[static_cast<size_t>(reg0)] = {};
            reg_info[static_cast<size_t>(reg1)] = {};

            auto p = std::make_pair(reg0, reg1);
            if (pair_reg_info.count(p) == 0) {
                invalidate_associated_pair_registers(reg0);
                invalidate_associated_pair_registers(reg1);
            }
            do_get(pair_reg_info[p], inst);
            break;
        }
        case IR::Opcode::SetExtendedRegister32: {
            Arm::ExtReg reg = inst->GetArg(0).GetExtRegRef();
            size_t reg_index = Arm::RegNumber(reg);
            do_set(ext_reg_singles_info[reg_index], inst->GetArg(1), inst);

            size_t doubles_reg_index = reg_index / 2;
            if (doubles_reg_index < ext_reg_doubles_info.size()) {
                ext_reg_doubles_info[doubles_reg_index] = {};
            }
            break;
        }
        case IR::Opcode::GetExtendedRegister32: {
            Arm::ExtReg reg = inst->GetArg(0).GetExtRegRef();
            size_t reg_index = Arm::RegNumber(reg);
            do_get(ext_reg_singles_info[reg_index], inst);

            size_t doubles_reg_index = reg_index / 2;
            if (doubles_reg_index < ext_reg_doubles_info.size()) {
                ext_reg_doubles_info[doubles_reg_index] = {};
            }
            break;
        }
        case IR::Opcode::SetExtendedRegister64: {
            Arm::ExtReg reg = inst->GetArg(0).GetExtRegRef();
            size_t reg_index = Arm::RegNumber(reg);
            do_set(ext_reg_doubles_info[reg_index], inst->GetArg(1), inst);

            size_t singles_reg_index = reg_index * 2;
            if (singles_reg_index < ext_reg_singles_info.size()) {
                ext_reg_singles_info[singles_reg_index] = {};
                ext_reg_singles_info[singles_reg_index+1] = {};
            }
            break;
        }
        case IR::Opcode::GetExtendedRegister64: {
            Arm::ExtReg reg = inst->GetArg(0).GetExtRegRef();
            size_t reg_index = Arm::RegNumber(reg);
            do_get(ext_reg_doubles_info[reg_index], inst);

            size_t singles_reg_index = reg_index * 2;
            if (singles_reg_index < ext_reg_singles_info.size()) {
                ext_reg_singles_info[singles_reg_index] = {};
                ext_reg_singles_info[singles_reg_index+1] = {};
            }
            break;
        }
        case IR::Opcode::SetNFlag: {
            do_set(cpsr_info.n, inst->GetArg(0), inst);
            break;
        }
        case IR::Opcode::GetNFlag: {
            do_get(cpsr_info.n, inst);
            break;
        }
        case IR::Opcode::SetZFlag: {
            do_set(cpsr_info.z, inst->GetArg(0), inst);
            break;
        }
        case IR::Opcode::GetZFlag: {
            do_get(cpsr_info.z, inst);
            break;
        }
        case IR::Opcode::SetCFlag: {
            do_set(cpsr_info.c, inst->GetArg(0), inst);
            break;
        }
        case IR::Opcode::GetCFlag: {
            do_get(cpsr_info.c, inst);
            break;
        }
        case IR::Opcode::SetVFlag: {
            do_set(cpsr_info.v, inst->GetArg(0), inst);
            break;
        }
        case IR::Opcode::GetVFlag: {
            do_get(cpsr_info.v, inst);
            break;
        }
        case IR::Opcode::SetGEFlags: {
            do_set(cpsr_info.ge, inst->GetArg(0), inst);
            break;
        }
        case IR::Opcode::GetGEFlags: {
            do_get(cpsr_info.ge, inst);
            break;
        }
        default: {
            if (inst->ReadsFromCPSR() || inst->WritesToCPSR()) {
                cpsr_info = {};
            }
            if (inst->CausesCPUException()) {
                reg_info = {};
                pair_reg_info = {};
                ext_reg_singles_info = {};
                ext_reg_doubles_info = {};
                cpsr_info = {};
            }
            break;
        }
        }
    }
}

static void ReducePass(IR::Block& block) {
    for (auto inst = block.begin(); inst != block.end(); ++inst) {
        switch (inst->GetOpcode()) {
        case IR::Opcode::SetRegisterPair: {
            Arm::Reg reg_lo = inst->GetArg(0).GetRegRef();
            Arm::Reg reg_hi = inst->GetArg(1).GetRegRef();
            IR::Value pair_value = inst->GetArg(2);

            IR::Inst* inst_lo = block.InsertInstBefore(&*inst, IR::Opcode::LeastSignificantWord, {pair_value});
            IR::Inst* inst_hi = block.InsertInstBefore(&*inst, IR::Opcode::MostSignificantWord, {pair_value});
            block.InsertInstBefore(&*inst, IR::Opcode::SetRegister, {IR::Value(reg_lo), IR::Value(inst_lo)});
            block.InsertInstBefore(&*inst, IR::Opcode::SetRegister, {IR::Value(reg_hi), IR::Value(inst_hi)});

            auto curr = inst--;
            curr->Invalidate();
            block.Instructions().erase(curr);
            break;
        }
        case IR::Opcode::GetRegisterPair: {
            Arm::Reg reg_lo = inst->GetArg(0).GetRegRef();
            Arm::Reg reg_hi = inst->GetArg(1).GetRegRef();

            IR::Inst* inst_lo = block.InsertInstBefore(&*inst, IR::Opcode::GetRegister, {IR::Value(reg_lo)});
            IR::Inst* inst_hi = block.InsertInstBefore(&*inst, IR::Opcode::GetRegister, {IR::Value(reg_hi)});
            IR::Inst* value = block.InsertInstBefore(&*inst, IR::Opcode::Pack2x32To1x64, {IR::Value(inst_lo), IR::Value(inst_hi)});

            inst->ReplaceUsesWith(IR::Value(value));
            break;
        }
        default:
            break;
        }
    }
}

void GetSetElimination(IR::Block& block) {
    ElimPass(block);
    ReducePass(block);
    ElimPass(block);
}

} // namespace Optimization
} // namespace Dynarmic

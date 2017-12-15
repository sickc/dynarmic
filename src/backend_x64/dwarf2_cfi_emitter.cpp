/* This file is part of the dynarmic project.
 * Copyright (c) 2017 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#include "backend_x64/block_of_code.h"
#include "backend_x64/dwarf2_cfi_emitter.h"
#include "common/assert.h"
#include "common/bit_util.h"
#include "common/common_types.h"

namespace Dynarmic {
namespace BackendX64 {

const Uleb128 DwarfCfiEmitter::RAX = {0};
const Uleb128 DwarfCfiEmitter::RDX = {1};
const Uleb128 DwarfCfiEmitter::RCX = {2};
const Uleb128 DwarfCfiEmitter::RBX = {3};
const Uleb128 DwarfCfiEmitter::RSI = {4};
const Uleb128 DwarfCfiEmitter::RDI = {5};
const Uleb128 DwarfCfiEmitter::RBP = {6};
const Uleb128 DwarfCfiEmitter::RSP = {7};
const Uleb128 DwarfCfiEmitter::R8 = {8};
const Uleb128 DwarfCfiEmitter::R9 = {9};
const Uleb128 DwarfCfiEmitter::R10 = {10};
const Uleb128 DwarfCfiEmitter::R11 = {11};
const Uleb128 DwarfCfiEmitter::R12 = {12};
const Uleb128 DwarfCfiEmitter::R13 = {13};
const Uleb128 DwarfCfiEmitter::R14 = {14};
const Uleb128 DwarfCfiEmitter::R15 = {15};
const Uleb128 DwarfCfiEmitter::RETURN_ADDRESS = {16};
const Uleb128 DwarfCfiEmitter::XMM0 = {17};
const Uleb128 DwarfCfiEmitter::XMM1 = {18};
const Uleb128 DwarfCfiEmitter::XMM2 = {19};
const Uleb128 DwarfCfiEmitter::XMM3 = {20};
const Uleb128 DwarfCfiEmitter::XMM4 = {21};
const Uleb128 DwarfCfiEmitter::XMM5 = {22};
const Uleb128 DwarfCfiEmitter::XMM6 = {23};
const Uleb128 DwarfCfiEmitter::XMM7 = {24};
const Uleb128 DwarfCfiEmitter::XMM8 = {25};
const Uleb128 DwarfCfiEmitter::XMM9 = {26};
const Uleb128 DwarfCfiEmitter::XMM10 = {27};
const Uleb128 DwarfCfiEmitter::XMM11 = {28};
const Uleb128 DwarfCfiEmitter::XMM12 = {29};
const Uleb128 DwarfCfiEmitter::XMM13 = {30};
const Uleb128 DwarfCfiEmitter::XMM14 = {31};
const Uleb128 DwarfCfiEmitter::XMM15 = {32};
const Uleb128 DwarfCfiEmitter::STMM0 = {33};
const Uleb128 DwarfCfiEmitter::STMM1 = {34};
const Uleb128 DwarfCfiEmitter::STMM2 = {35};
const Uleb128 DwarfCfiEmitter::STMM3 = {36};
const Uleb128 DwarfCfiEmitter::STMM4 = {37};
const Uleb128 DwarfCfiEmitter::STMM5 = {38};
const Uleb128 DwarfCfiEmitter::STMM6 = {39};
const Uleb128 DwarfCfiEmitter::STMM7 = {40};
const Uleb128 DwarfCfiEmitter::MM0 = {41};
const Uleb128 DwarfCfiEmitter::MM1 = {42};
const Uleb128 DwarfCfiEmitter::MM2 = {43};
const Uleb128 DwarfCfiEmitter::MM3 = {44};
const Uleb128 DwarfCfiEmitter::MM4 = {45};
const Uleb128 DwarfCfiEmitter::MM5 = {46};
const Uleb128 DwarfCfiEmitter::MM6 = {47};
const Uleb128 DwarfCfiEmitter::MM7 = {48};
const Uleb128 DwarfCfiEmitter::RFLAGS = {49};
const Uleb128 DwarfCfiEmitter::ES = {50};
const Uleb128 DwarfCfiEmitter::CS = {51};
const Uleb128 DwarfCfiEmitter::SS = {52};
const Uleb128 DwarfCfiEmitter::DS = {53};
const Uleb128 DwarfCfiEmitter::FS = {54};
const Uleb128 DwarfCfiEmitter::GS = {55};
const Uleb128 DwarfCfiEmitter::FSBASE = {58};
const Uleb128 DwarfCfiEmitter::GSBASE = {59};
const Uleb128 DwarfCfiEmitter::TR = {62};
const Uleb128 DwarfCfiEmitter::LDTR = {63};
const Uleb128 DwarfCfiEmitter::MXCSR = {64};
const Uleb128 DwarfCfiEmitter::FCW = {65};
const Uleb128 DwarfCfiEmitter::FSW = {66};

DwarfExpressionEmitter::DwarfExpressionEmitter(BlockOfCode*) {
    ASSERT_MSG(false, "DwarfExpressionEmitter unimplemented");
}

DwarfCfiEmitter::DwarfCfiEmitter(BlockOfCode* block_of_code) : code(block_of_code) {}

// Row creation instructions

/// DW_CFA_set_loc
void DwarfCfiEmitter::SetLocation(u64 loc) {
    WriteOpcode(0x0, 0x01);
    dq(loc);
}

/// DW_CFA_advance_loc
void DwarfCfiEmitter::AdvanceLocationU6(u8 factored_delta) {
    ASSERT(factored_delta <= 0x1F);
    WriteOpcode(0x1, factored_delta);
}

/// DW_CFA_advance_loc1
void DwarfCfiEmitter::AdvanceLocationU8(u8 factored_delta) {
    WriteOpcode(0x0, 0x02);
    db(factored_delta);
}

/// DW_CFA_advance_loc2
void DwarfCfiEmitter::AdvanceLocationU16(u16 factored_delta) {
    WriteOpcode(0x0, 0x03);
    dw(factored_delta);
}

/// DW_CFA_advance_loc4
void DwarfCfiEmitter::AdvanceLocationU16(u32 factored_delta) {
    WriteOpcode(0x0, 0x04);
    dd(factored_delta);
}

// CFA Definition instructions

/// DW_CFA_def_cfa
void DwarfCfiEmitter::DefineCfa(Uleb128 register_number, Uleb128 factored_offset) {
    WriteOpcode(0x0, 0x0C);
    WriteUleb128(register_number);
    WriteUleb128(factored_offset);
}

/// DW_CFA_def_cfa_sf
void DwarfCfiEmitter::DefineCfaSigned(Uleb128 register_number, Sleb128 factored_offset) {
    WriteOpcode(0x0, 0x12);
    WriteUleb128(register_number);
    WriteSleb128(factored_offset);
}

/// DW_CFA_def_cfa_register
void DwarfCfiEmitter::DefineCfaRegister(Uleb128 register_number) {
    WriteOpcode(0x0, 0x0D);
    WriteUleb128(register_number);
}

/// DW_CFA_def_cfa_offset
void DwarfCfiEmitter::DefineCfaOffset(Uleb128 factored_offset) {
    WriteOpcode(0x0, 0x0E);
    WriteUleb128(factored_offset);
}

/// DW_CFA_def_cfa_offset_sf
void DwarfCfiEmitter::DefineCfaOffsetSigned(Sleb128 factored_offset) {
    WriteOpcode(0x0, 0x13);
    WriteSleb128(factored_offset);
}

// Register rule instructions

/// DW_CFA_undefined
void DwarfCfiEmitter::Undefined(Uleb128 register_number) {
    WriteOpcode(0x0, 0x07);
    WriteUleb128(register_number);
}

/// DW_CFA_same_value
void DwarfCfiEmitter::SameValue(Uleb128 register_number) {
    WriteOpcode(0x0, 0x08);
    WriteUleb128(register_number);
}

/// DW_CFA_offset
void DwarfCfiEmitter::Offset(u8 register_number, Uleb128 factored_offset) {
    ASSERT(register_number <= 0x1F);
    WriteOpcode(0x2, register_number);
    WriteUleb128(factored_offset);
}

/// DW_CFA_offset_extended
void DwarfCfiEmitter::OffsetExtended(Uleb128 register_number, Uleb128 factored_offset) {
    WriteOpcode(0x0, 0x05);
    WriteUleb128(register_number);
    WriteUleb128(factored_offset);
}

/// DW_CFA_offset_extended_sf
void DwarfCfiEmitter::OffsetExtendedSigned(Uleb128 register_number, Sleb128 factored_offset) {
    WriteOpcode(0x0, 0x11);
    WriteUleb128(register_number);
    WriteSleb128(factored_offset);
}

/// DW_CFA_val_offset
void DwarfCfiEmitter::ValueOffset(Uleb128 register_number, Uleb128 factored_offset) {
    WriteOpcode(0x0, 0x14);
    WriteUleb128(register_number);
    WriteUleb128(factored_offset);
}

/// DW_CFA_val_offset_sf
void DwarfCfiEmitter::ValueOffsetSigned(Uleb128 register_number, Sleb128 factored_offset) {
    WriteOpcode(0x0, 0x15);
    WriteUleb128(register_number);
    WriteSleb128(factored_offset);
}

/// DW_CFA_register
void DwarfCfiEmitter::Register(Uleb128 register_a, Uleb128 register_b) {
    WriteOpcode(0x0, 0x09);
    WriteUleb128(register_a);
    WriteUleb128(register_b);
}

/// DW_CFA_restore
void DwarfCfiEmitter::Restore(u8 register_number) {
    ASSERT(register_number <= 0x1F);
    WriteOpcode(0x3, register_number);
}

/// DW_CFA_restore_extended
void DwarfCfiEmitter::RestoreExtended(Uleb128 register_number) {
    WriteOpcode(0x0, 0x06);
    WriteUleb128(register_number);
}

// Row state instructions

/// DW_CFA_remember_state
void DwarfCfiEmitter::RememberState() {
    WriteOpcode(0x0, 0x0A);
}

/// DW_CFA_restore_state
void DwarfCfiEmitter::RestoreState() {
    WriteOpcode(0x0, 0x0B);
}

// Padding instruction

/// DW_CFA_nop
void DwarfCfiEmitter::Nop() {
    WriteOpcode(0x0, 0x00);
}

void DwarfCfiEmitter::Align(size_t alignment) {
    while (reinterpret_cast<size_t>(code->getCurr()) % alignment != 0) {
        Nop();
    }
}

void DwarfCfiEmitter::WriteOpcode(u8 high, u8 low) {
    ASSERT(high <= 0x3);
    ASSERT(low <= 0x1F);

    db((high << 6) | low);
}

void DwarfCfiEmitter::WriteUleb128(Uleb128 uleb128) {
    u64 v = uleb128.value;
    while (true) {
        u8 current_byte = v & 0x7F;
        v >>= 7;

        if (v == 0) {
            db(current_byte);
            return;
        }
        
        db(0x80 | current_byte);
    } 
}

void DwarfCfiEmitter::WriteSleb128(Sleb128 uleb128) {
    s64 v = uleb128.value;
    while (true) {
        u8 current_byte = v & 0x7F;
        v >>= 7;

        if ((v == 0 && !Common::Bit<6>(current_byte)) || (v == -1 && Common::Bit<6>(current_byte))) {
            db(current_byte);
            return;
        }

        db(0x80 | current_byte);
    }
}

void DwarfCfiEmitter::db(u8 b) {
    code->db(b);
}

void DwarfCfiEmitter::dw(u16 w) {
    code->dw(w);
}

void DwarfCfiEmitter::dd(u32 d) {
    code->dd(d);
}

void DwarfCfiEmitter::dq(u64 q) {
    code->dq(q);
}

} // namespace BackendX64
} // namespace Dynarmic

/* This file is part of the dynarmic project.
 * Copyright (c) 2017 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#include "common/common_types.h"
#include "backend_x64/block_of_code.h"

namespace Dynarmic {
namespace BackendX64 {

struct Uleb128 {
    u64 value;
};

struct Sleb128 {
    s64 value;
};

class DwarfExpressionEmitter final {
public:
    explicit DwarfExpressionEmitter(BlockOfCode* block_of_code);
};

/**
 * Emits DWARF Call Frame Information
 * Documentation:
 * - http://dwarfstd.org/doc/DWARF4.pdf
 * - http://dwarfstd.org/doc/DWARF5.pdf
 */
class DwarfCfiEmitter final {
public:
    explicit DwarfCfiEmitter(BlockOfCode* block_of_code);

    // x64 column names
    // Documentation: https://www.uclibc.org/docs/psABI-x86_64.pdf

    static const Uleb128 RAX;
    static const Uleb128 RDX;
    static const Uleb128 RCX;
    static const Uleb128 RBX;
    static const Uleb128 RSI;
    static const Uleb128 RDI;
    static const Uleb128 RBP;
    static const Uleb128 RSP;
    static const Uleb128 R8;
    static const Uleb128 R9;
    static const Uleb128 R10;
    static const Uleb128 R11;
    static const Uleb128 R12;
    static const Uleb128 R13;
    static const Uleb128 R14;
    static const Uleb128 R15;
    static const Uleb128 RETURN_ADDRESS;
    static const Uleb128 XMM0;
    static const Uleb128 XMM1;
    static const Uleb128 XMM2;
    static const Uleb128 XMM3;
    static const Uleb128 XMM4;
    static const Uleb128 XMM5;
    static const Uleb128 XMM6;
    static const Uleb128 XMM7;
    static const Uleb128 XMM8;
    static const Uleb128 XMM9;
    static const Uleb128 XMM10;
    static const Uleb128 XMM11;
    static const Uleb128 XMM12;
    static const Uleb128 XMM13;
    static const Uleb128 XMM14;
    static const Uleb128 XMM15;
    static const Uleb128 STMM0;
    static const Uleb128 STMM1;
    static const Uleb128 STMM2;
    static const Uleb128 STMM3;
    static const Uleb128 STMM4;
    static const Uleb128 STMM5;
    static const Uleb128 STMM6;
    static const Uleb128 STMM7;
    static const Uleb128 MM0;
    static const Uleb128 MM1;
    static const Uleb128 MM2;
    static const Uleb128 MM3;
    static const Uleb128 MM4;
    static const Uleb128 MM5;
    static const Uleb128 MM6;
    static const Uleb128 MM7;
    static const Uleb128 RFLAGS;
    static const Uleb128 ES;
    static const Uleb128 CS;
    static const Uleb128 SS;
    static const Uleb128 DS;
    static const Uleb128 FS;
    static const Uleb128 GS;
    // 56-57 are reserved
    static const Uleb128 FSBASE;
    static const Uleb128 GSBASE;
    // 60-61 are reserved
    static const Uleb128 TR; ///< Task Register
    static const Uleb128 LDTR;
    static const Uleb128 MXCSR;
    static const Uleb128 FCW;
    static const Uleb128 FSW;

    // Pointer encoding specification byte

    enum class PointerEncodingSpecification {
        StoredAsLeb128 = 0x01,
        StoredAsTwoByteInteger = 0x02,
        StoredAsFourByteInteger = 0x03,
        StoredAsEightByteInteger = 0x04,
        Signed = 0x08,
        RelativeToPC = 0x10,
        RelativeToTextSection = 0x20,
        RelativeToDataSection = 0x30,
        RelativeToStartOfFunction = 0x40,
    };

    // Row creation instructions

    /// DW_CFA_set_loc
    void SetLocation(u64 loc);

    /// DW_CFA_advance_loc
    void AdvanceLocationU6(u8 factored_delta);

    /// DW_CFA_advance_loc1
    void AdvanceLocationU8(u8 factored_delta);

    /// DW_CFA_advance_loc2
    void AdvanceLocationU16(u16 factored_delta);

    /// DW_CFA_advance_loc4
    void AdvanceLocationU16(u32 factored_delta);

    // CFA Definition instructions

    /// DW_CFA_def_cfa
    void DefineCfa(Uleb128 register_number, Uleb128 factored_offset);

    /// DW_CFA_def_cfa_sf
    void DefineCfaSigned(Uleb128 register_number, Sleb128 factored_offset);

    /// DW_CFA_def_cfa_register
    void DefineCfaRegister(Uleb128 register_number);

    /// DW_CFA_def_cfa_offset
    void DefineCfaOffset(Uleb128 factored_offset);

    /// DW_CFA_def_cfa_offset_sf
    void DefineCfaOffsetSigned(Sleb128 factored_offset);

    /// DW_CFA_def_expression
    template <typename F>
    void DefineCfaExpression(F f) {
        WriteOpcode(0x0, 0x0F);
        f(DwarfExpressionEmitter{code});
    }

    // Register rule instructions

    /// DW_CFA_undefined
    void Undefined(Uleb128 register_number);

    /// DW_CFA_same_value
    void SameValue(Uleb128 register_number);

    /// DW_CFA_offset
    void Offset(u8 register_number, Uleb128 factored_offset);

    /// DW_CFA_offset_extended
    void OffsetExtended(Uleb128 register_number, Uleb128 factored_offset);

    /// DW_CFA_offset_extended_sf
    void OffsetExtendedSigned(Uleb128 register_number, Sleb128 factored_offset);

    /// DW_CFA_val_offset
    void ValueOffset(Uleb128 register_number, Uleb128 factored_offset);

    /// DW_CFA_val_offset_sf
    void ValueOffsetSigned(Uleb128 register_number, Sleb128 factored_offset);

    /// DW_CFA_register
    void Register(Uleb128 register_a, Uleb128 register_b);

    /// DW_CFA_expression
    template <typename F>
    void Expression(Uleb128 register_number, F f) {
        WriteOpcode(0x0, 0x10);
        WriteUleb128(register_number);
        f(DwarfExpressionEmitter{code});
    }

    /// DW_CFA_val_expression
    template <typename F>
    void ValueExpression(Uleb128 register_number, F f) {
        WriteOpcode(0x0, 0x16);
        WriteUleb128(register_number);
        f(DwarfExpressionEmitter{code});
    }

    /// DW_CFA_restore
    void Restore(u8 register_number);

    /// DW_CFA_restore_extended
    void RestoreExtended(Uleb128 register_number);

    // Row state instructions

    /// DW_CFA_remember_state
    void RememberState();

    /// DW_CFA_restore_state
    void RestoreState();

    // Padding instruction

    /// DW_CFA_nop
    void Nop();

    void Align(size_t alignment = 8);

    void WriteOpcode(u8 low, u8 high);
    void WriteUleb128(Uleb128 uleb128);
    void WriteSleb128(Sleb128 uleb128);
    void db(u8 b);
    void dw(u16 w);
    void dd(u32 d);
    void dq(u64 q);

    template <typename T>
    T getCurr() const {
        return code->getCurr<T>();
    }

private:
    BlockOfCode* code;
};

} // namespace BackendX64
} // namespace Dynarmic

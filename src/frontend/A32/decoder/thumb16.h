/* This file is part of the dynarmic project.
 * Copyright (c) 2016 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#pragma once

#include <algorithm>
#include <functional>
#include <optional>
#include <vector>

#include <dynarmic/A32/arch_version.h>

#include "common/common_types.h"
#include "frontend/A32/matcher.h"
#include "frontend/decoder/decoder_detail.h"

namespace Dynarmic::A32 {

template <typename Visitor>
using Thumb16Matcher = Matcher<Visitor, u16>;

template<typename V>
std::optional<std::reference_wrapper<const Thumb16Matcher<V>>> DecodeThumb16(u16 instruction) {
    static const std::vector<Thumb16Matcher<V>> table = {

#define INST(fn, name, bitstring, ver) Decoder::detail::detail<Thumb16Matcher<V>>::GetMatcher(&V::fn, name, bitstring, ArchVersion::ver)

        // Shift (immediate), add, subtract, move and compare instructions
        INST(thumb16_LSL_imm,       "LSL (imm)",                "00000vvvvvmmmddd", v4T),
        INST(thumb16_LSR_imm,       "LSR (imm)",                "00001vvvvvmmmddd", v4T),
        INST(thumb16_ASR_imm,       "ASR (imm)",                "00010vvvvvmmmddd", v4T),
        INST(thumb16_ADD_reg_t1,    "ADD (reg, T1)",            "0001100mmmnnnddd", v4T),
        INST(thumb16_SUB_reg,       "SUB (reg)",                "0001101mmmnnnddd", v4T),
        INST(thumb16_ADD_imm_t1,    "ADD (imm, T1)",            "0001110vvvnnnddd", v4T),
        INST(thumb16_SUB_imm_t1,    "SUB (imm, T1)",            "0001111vvvnnnddd", v4T),
        INST(thumb16_MOV_imm,       "MOV (imm)",                "00100dddvvvvvvvv", v4T),
        INST(thumb16_CMP_imm,       "CMP (imm)",                "00101nnnvvvvvvvv", v4T),
        INST(thumb16_ADD_imm_t2,    "ADD (imm, T2)",            "00110dddvvvvvvvv", v4T),
        INST(thumb16_SUB_imm_t2,    "SUB (imm, T2)",            "00111dddvvvvvvvv", v4T),

        // Data-processing instructions
        INST(thumb16_AND_reg,       "AND (reg)",                "0100000000mmmddd", v4T),
        INST(thumb16_EOR_reg,       "EOR (reg)",                "0100000001mmmddd", v4T),
        INST(thumb16_LSL_reg,       "LSL (reg)",                "0100000010mmmddd", v4T),
        INST(thumb16_LSR_reg,       "LSR (reg)",                "0100000011mmmddd", v4T),
        INST(thumb16_ASR_reg,       "ASR (reg)",                "0100000100mmmddd", v4T),
        INST(thumb16_ADC_reg,       "ADC (reg)",                "0100000101mmmddd", v4T),
        INST(thumb16_SBC_reg,       "SBC (reg)",                "0100000110mmmddd", v4T),
        INST(thumb16_ROR_reg,       "ROR (reg)",                "0100000111sssddd", v4T),
        INST(thumb16_TST_reg,       "TST (reg)",                "0100001000mmmnnn", v4T),
        INST(thumb16_RSB_imm,       "RSB (imm)",                "0100001001nnnddd", v4T),
        INST(thumb16_CMP_reg_t1,    "CMP (reg, T1)",            "0100001010mmmnnn", v4T),
        INST(thumb16_CMN_reg,       "CMN (reg)",                "0100001011mmmnnn", v4T),
        INST(thumb16_ORR_reg,       "ORR (reg)",                "0100001100mmmddd", v4T),
        INST(thumb16_MUL_reg,       "MUL (reg)",                "0100001101nnnddd", v4T),
        INST(thumb16_BIC_reg,       "BIC (reg)",                "0100001110mmmddd", v4T),
        INST(thumb16_MVN_reg,       "MVN (reg)",                "0100001111mmmddd", v4T),

        // Special data instructions
        INST(thumb16_ADD_reg_t2,    "ADD (reg, T2)",            "01000100Dmmmmddd", v4T), // Low regs: v6T2
        INST(thumb16_CMP_reg_t2,    "CMP (reg, T2)",            "01000101Nmmmmnnn", v4T),
        INST(thumb16_MOV_reg,       "MOV (reg)",                "01000110Dmmmmddd", v4T), // Low regs: v6

        // Store/Load single data item instructions
        INST(thumb16_LDR_literal,   "LDR (literal)",            "01001tttvvvvvvvv", v4T),
        INST(thumb16_STR_reg,       "STR (reg)",                "0101000mmmnnnttt", v4T),
        INST(thumb16_STRH_reg,      "STRH (reg)",               "0101001mmmnnnttt", v4T),
        INST(thumb16_STRB_reg,      "STRB (reg)",               "0101010mmmnnnttt", v4T),
        INST(thumb16_LDRSB_reg,     "LDRSB (reg)",              "0101011mmmnnnttt", v4T),
        INST(thumb16_LDR_reg,       "LDR (reg)",                "0101100mmmnnnttt", v4T),
        INST(thumb16_LDRH_reg,      "LDRH (reg)",               "0101101mmmnnnttt", v4T),
        INST(thumb16_LDRB_reg,      "LDRB (reg)",               "0101110mmmnnnttt", v4T),
        INST(thumb16_LDRSH_reg,     "LDRSH (reg)",              "0101111mmmnnnttt", v4T),
        INST(thumb16_STR_imm_t1,    "STR (imm, T1)",            "01100vvvvvnnnttt", v4T),
        INST(thumb16_LDR_imm_t1,    "LDR (imm, T1)",            "01101vvvvvnnnttt", v4T),
        INST(thumb16_STRB_imm,      "STRB (imm)",               "01110vvvvvnnnttt", v4T),
        INST(thumb16_LDRB_imm,      "LDRB (imm)",               "01111vvvvvnnnttt", v4T),
        INST(thumb16_STRH_imm,      "STRH (imm)",               "10000vvvvvnnnttt", v4T),
        INST(thumb16_LDRH_imm,      "LDRH (imm)",               "10001vvvvvnnnttt", v4T),
        INST(thumb16_STR_imm_t2,    "STR (imm, T2)",            "10010tttvvvvvvvv", v4T),
        INST(thumb16_LDR_imm_t2,    "LDR (imm, T2)",            "10011tttvvvvvvvv", v4T),

        // Generate relative address instructions
        INST(thumb16_ADR,           "ADR",                      "10100dddvvvvvvvv", v4T),
        INST(thumb16_ADD_sp_t1,     "ADD (SP plus imm, T1)",    "10101dddvvvvvvvv", v4T),
        INST(thumb16_ADD_sp_t2,     "ADD (SP plus imm, T2)",    "101100000vvvvvvv", v4T),
        INST(thumb16_SUB_sp,        "SUB (SP minus imm)",       "101100001vvvvvvv", v4T),

        // Miscellaneous 16-bit instructions
        INST(thumb16_SXTH,          "SXTH",                     "1011001000mmmddd", v6),
        INST(thumb16_SXTB,          "SXTB",                     "1011001001mmmddd", v6),
        INST(thumb16_UXTH,          "UXTH",                     "1011001010mmmddd", v6),
        INST(thumb16_UXTB,          "UXTB",                     "1011001011mmmddd", v6),
        INST(thumb16_PUSH,          "PUSH",                     "1011010Mxxxxxxxx", v4T),
        INST(thumb16_SETEND,        "SETEND",                   "101101100101x000", v6),
        INST(thumb16_CPS,           "CPS",                      "10110110011m0aif", v6),
        INST(thumb16_REV,           "REV",                      "1011101000mmmddd", v6),
        INST(thumb16_REV16,         "REV16",                    "1011101001mmmddd", v6),
        INST(thumb16_REVSH,         "REVSH",                    "1011101011mmmddd", v6),
        INST(thumb16_POP,           "POP",                      "1011110Pxxxxxxxx", v4T),
        INST(thumb16_BKPT,          "BKPT",                     "10111110xxxxxxxx", v5T),

        // Hint instructions
        INST(thumb16_SEV,           "SEV",                      "1011111101000000", v7),
        INST(thumb16_SEVL,          "SEVL",                     "1011111101010000", v8),
        INST(thumb16_WFE,           "WFE",                      "1011111100100000", v7),
        INST(thumb16_WFI,           "WFI",                      "1011111100110000", v7),
        INST(thumb16_YIELD,         "YIELD",                    "1011111100010000", v7),
        INST(thumb16_NOP,           "NOP",                      "10111111----0000", v6T2),

        // If-Then
        INST(thumb16_IT,            "IT",                       "10111111ccccxxxx", v6T2),

        // Store/Load multiple registers
        INST(thumb16_STMIA,         "STMIA",                    "11000nnnxxxxxxxx", v4T),
        INST(thumb16_LDMIA,         "LDMIA",                    "11001nnnxxxxxxxx", v4T),

        // Branch instructions
        INST(thumb16_BX,            "BX",                       "010001110mmmm000", v4T),
        INST(thumb16_BLX_reg,       "BLX (reg)",                "010001111mmmm000", v5T),
        INST(thumb16_CBZ_CBNZ,      "CBZ/CBNZ",                 "1011o0i1iiiiinnn", v6T2),
        INST(thumb16_UDF,           "UDF",                      "11011110--------", v4T),
        INST(thumb16_SVC,           "SVC",                      "11011111xxxxxxxx", v4T),
        INST(thumb16_B_t1,          "B (T1)",                   "1101ccccvvvvvvvv", v4T),
        INST(thumb16_B_t2,          "B (T2)",                   "11100vvvvvvvvvvv", v4T),

#undef INST

    };

    const auto matches_instruction = [instruction](const auto& matcher){ return matcher.Matches(instruction); };

    auto iter = std::find_if(table.begin(), table.end(), matches_instruction);
    return iter != table.end() ? std::optional<std::reference_wrapper<const Thumb16Matcher<V>>>(*iter) : std::nullopt;
}

} // namespace Dynarmic::A32

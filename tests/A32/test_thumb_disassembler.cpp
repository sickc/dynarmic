/* This file is part of the dynarmic project.
 * Copyright (c) 2019 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#include <catch.hpp>

#include "frontend/A32/disassembler/disassembler.h"

using Dynarmic::A32::DisassembleThumb16;

TEST_CASE("Disassemble if-then instructions", "[thumb][disassembler]") {
    REQUIRE(DisassembleThumb16(0xBF01) == "itttt eq");
    REQUIRE(DisassembleThumb16(0xBF02) == "ittt eq");
    REQUIRE(DisassembleThumb16(0xBF03) == "ittte eq");
    REQUIRE(DisassembleThumb16(0xBF04) == "itt eq");
    REQUIRE(DisassembleThumb16(0xBF05) == "ittet eq");
    REQUIRE(DisassembleThumb16(0xBF06) == "itte eq");
    REQUIRE(DisassembleThumb16(0xBF07) == "ittee eq");
    REQUIRE(DisassembleThumb16(0xBF08) == "it eq");
    REQUIRE(DisassembleThumb16(0xBF09) == "itett eq");
    REQUIRE(DisassembleThumb16(0xBF0A) == "itet eq");
    REQUIRE(DisassembleThumb16(0xBF0B) == "itete eq");
    REQUIRE(DisassembleThumb16(0xBF0C) == "ite eq");
    REQUIRE(DisassembleThumb16(0xBF0D) == "iteet eq");
    REQUIRE(DisassembleThumb16(0xBF0E) == "itee eq");
    REQUIRE(DisassembleThumb16(0xBF0F) == "iteee eq");
    REQUIRE(DisassembleThumb16(0xBF11) == "iteee ne");
    REQUIRE(DisassembleThumb16(0xBF12) == "itee ne");
    REQUIRE(DisassembleThumb16(0xBF13) == "iteet ne");
    REQUIRE(DisassembleThumb16(0xBF14) == "ite ne");
    REQUIRE(DisassembleThumb16(0xBF15) == "itete ne");
    REQUIRE(DisassembleThumb16(0xBF16) == "itet ne");
    REQUIRE(DisassembleThumb16(0xBF17) == "itett ne");
    REQUIRE(DisassembleThumb16(0xBF18) == "it ne");
    REQUIRE(DisassembleThumb16(0xBF19) == "ittee ne");
    REQUIRE(DisassembleThumb16(0xBF1A) == "itte ne");
    REQUIRE(DisassembleThumb16(0xBF1B) == "ittet ne");
    REQUIRE(DisassembleThumb16(0xBF1C) == "itt ne");
    REQUIRE(DisassembleThumb16(0xBF1D) == "ittte ne");
    REQUIRE(DisassembleThumb16(0xBF1E) == "ittt ne");
    REQUIRE(DisassembleThumb16(0xBF1F) == "itttt ne");
}

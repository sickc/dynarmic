/* This file is part of the dynarmic project.
 * Copyright (c) 2019 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#include <catch.hpp>
#include <fmt/format.h>

#include "backend/x64/a32_jitstate.h"
#include "backend/x64/block_of_code.h"
#include "backend/x64/exception_handler.h"
#include "common/cast_util.h"

using namespace Dynarmic;
using namespace Dynarmic::BackendX64;

static void nullfn() {}
static BlockOfCode MakeBlockOfCode() {
    return BlockOfCode{RunCodeCallbacks{
        std::make_unique<SimpleCallback>(&nullfn),
        std::make_unique<SimpleCallback>(&nullfn),
        std::make_unique<SimpleCallback>(&nullfn),
        0,
    }, JitStateInfo{A32JitState{}}};
}

TEST_CASE("Exception handler sanity check", "[backend/x64]") {
    using namespace Xbyak::util;

    BlockOfCode code = MakeBlockOfCode();
    ExceptionHandler exception_handler;
    exception_handler.Register(code);

    code.align(16);
    const auto f = code.getCurr<int(*)()>();
    code.mov(rax, 42);
    code.ret();

    REQUIRE(f() == 42);
}

TEST_CASE("Exception handler callback works", "[backend/x64]") {
    using namespace Xbyak::util;

    const auto cb = [](X64State& ts){
        ts.rip += 6; // Skip over mov dword [rax], 0 instruction
        ts.gpr[0] = 42;
    };

    BlockOfCode code = MakeBlockOfCode();
    ExceptionHandler exception_handler;
    exception_handler.Register(code, std::make_unique<SimpleCallback>(static_cast<void(*)(X64State&)>(cb)));

    if (!exception_handler.SupportsFastMem()) {
        fmt::print(stderr, "WARNING: Exception callbacks not supported!\n");
        return;
    }

    code.align(16);
    const auto f = code.getCurr<int(*)()>();
    code.sub(rsp, 8);
    code.mov(rax, 0);
    code.mov(dword[rax], 0);
    code.add(rsp, 8);
    code.ret();

    REQUIRE(f() == 42);
}

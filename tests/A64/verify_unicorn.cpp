/* This file is part of the dynarmic project.
 * Copyright (c) 2018 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#include <array>
#include <tuple>
#include <vector>

#include <catch.hpp>

#include "rand_int.h"
#include "testenv.h"
#include "unicorn_emu/unicorn.h"

using namespace Dynarmic;

TEST_CASE("Unicorn: Sanity test", "[a64]") {
    TestEnv env;
    env.code_mem[0] = 0x8b020020; // ADD X0, X1, X2
    env.code_mem[1] = 0x14000000; // B .

    constexpr Unicorn::RegisterArray regs{
        0, 1, 2, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0
    };

    Unicorn unicorn{env};

    unicorn.SetRegisters(regs);
    unicorn.SetPC(0);

    env.ticks_left = 2;
    unicorn.Run();

    REQUIRE(unicorn.GetRegisters()[0] == 3);
    REQUIRE(unicorn.GetRegisters()[1] == 1);
    REQUIRE(unicorn.GetRegisters()[2] == 2);
    REQUIRE(unicorn.GetPC() == 4);
}

TEST_CASE("Unicorn: Ensure 0xFFFF'FFFF'FFFF'FFFF is readable", "[a64]") {
    TestEnv env;

    env.code_mem[0] = 0x385fed99; // LDRB W25, [X12, #0xfffffffffffffffe]!
    env.code_mem[1] = 0x14000000; // B .

    Unicorn::RegisterArray regs{};
    regs[12] = 1;

    Unicorn unicorn{env};

    unicorn.SetRegisters(regs);
    unicorn.SetPC(0);

    env.ticks_left = 2;
    unicorn.Run();

    REQUIRE(unicorn.GetPC() == 4);
}

TEST_CASE("Unicorn: Ensure is able to read across page boundaries", "[a64]") {
    TestEnv env;

    env.code_mem[0] = 0xb85f93d9; // LDUR W25, [X30, #0xfffffffffffffff9]
    env.code_mem[1] = 0x14000000; // B .

    Unicorn::RegisterArray regs{};
    regs[30] = 4;

    Unicorn unicorn{env};

    unicorn.SetRegisters(regs);
    unicorn.SetPC(0);

    env.ticks_left = 2;
    unicorn.Run();

    REQUIRE(unicorn.GetPC() == 4);
}

TEST_CASE("Unicorn: FDIV", "[a64]") {
    TestEnv env;

    env.code_mem[0] = 0x1e621820; // FDIV D0, D1, D2
    env.code_mem[1] = 0x14000000; // B .

    const std::vector<std::tuple<u64, u64, u64>> test_cases {
        { 0x8c198d264cfbc18b, 0x8ba98d277f800001, 0x3f800000bff00000 },
        { 0xfd855554b6f44c59, 0xffbfffff7fc00000, 0x4228000051fd2c7c },
        { 0xf61f9a79a976a643, 0xbf800000bf5a97c9, 0x09503366ff7fffff },
        { 0xe5018b7801779a5c, 0xe73a5134ff800001, 0x42280000e6ff1a14 },
        { 0xff5ffffffff00000, 0xbff000007ff00000, 0x008000007ff80000 },
//        { 0x897108fc1b78a42e, 0x0966320bc79b271e, 0x8ba98d7a80800000 },
        { 0x80d36d244476b4cf, 0x00636d24807fffff, 0xbf800000317285d3 },
        { 0x358f8538873c3a27, 0xf51f853a7f7fffff, 0xff800000fff80000 },
        { 0x40dffffffff00000, 0x3ff000007ff00000, 0x3f0000007ff80000 },
        { 0x3feffffffff00000, 0xff8000007ff00000, 0xff8000007ff80000 },
//        { 0x41333333897cbb9c, 0x3ff00000c79b271e, 0x3eaaaaab7f7fffff },
//        { 0x00eda132e63eda2c, 0x80800002460e8c84, 0xbf8147ae7fbfffff },
        { 0x0d3a9916b63e367e, 0xbd7caffc2d497f4f, 0xf03141c42dbf7195 }, // https://travis-ci.org/MerryMage/dynarmic/jobs/404107002
//        { 0x3c006a6c04ef0dd0, 0x7b906a6c80000076, 0x7f80000077f31e2f }, // https://travis-ci.org/MerryMage/dynarmic/jobs/403563493
        { 0x406ffffffff00002, 0x3f8000007ff80000, 0x3f0000007fffffff }, // https://travis-ci.org/MerryMage/dynarmic/jobs/401219421
        { 0x3feffffe00781ff2, 0xffbffffffff80000, 0xffc00000ffbfffff }, // https://travis-ci.org/MerryMage/dynarmic/jobs/401075459
    };

    for (const auto [d0, d1, d2] : test_cases) {
        INFO("Expecting: " << std::hex << d0);
        printf("%llx\n", d0);

        Unicorn::VectorArray vecs{};
        vecs[0] = {0, 0};
        vecs[1] = {d1, 0};
        vecs[2] = {d2, 0};

        Unicorn unicorn{env};

        unicorn.SetVectors(vecs);
        unicorn.SetPC(0);

        env.ticks_left = 2;
        unicorn.Run();

        if (unicorn.GetVectors()[0] != Vector{d0, 0}) {
            printf("wrong %llx %llx\n", d0, unicorn.GetVectors()[0][0]);
        }
    }

    printf("end of experiment\n\n");
}

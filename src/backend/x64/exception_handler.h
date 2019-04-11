/* This file is part of the dynarmic project.
 * Copyright (c) 2016 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#pragma once

#include <array>
#include <memory>

#include "backend/x64/callback.h"
#include "common/common_types.h"

namespace Dynarmic::BackendX64 {

class BlockOfCode;

struct X64State {
    using Vector = std::array<u64, 2>;

    std::array<u64, 16> gpr;
    std::array<Vector, 16> xmm;
    u64 rip;
    u64 flags;
};

class ExceptionHandler final {
public:
    ExceptionHandler();
    ~ExceptionHandler();

    void Register(BlockOfCode& code, std::unique_ptr<Callback> segv_callback = nullptr);

    bool SupportsFastMem() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace Dynarmic::BackendX64

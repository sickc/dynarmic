/* This file is part of the dynarmic project.
 * Copyright (c) 2019 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#pragma once

#include "common/common_types.h"
#include "common/bit_util.h"
#include "frontend/ir/cond.h"

namespace Dynarmic::A32 {

class ITState final {
public:
    ITState() = default;
    explicit ITState(u8 data) : value(data) {}
    ITState(IR::Cond cond, u8 mask) {
        Cond(cond);
        Mask(mask);
    }

    ITState& operator=(u8 data) {
        value = data;
        return *this;
    }

    IR::Cond Cond() const {
        return static_cast<IR::Cond>(Common::Bits<4, 7>(value));
    }
    void Cond(IR::Cond cond) {
        value = Common::ModifyBits<4, 7>(value, static_cast<u8>(cond));
    }

    u8 Mask() const {
        return Common::Bits<0, 3>(value);
    }
    void Mask(u8 mask) {
        value = Common::ModifyBits<0, 3>(value, mask);
    }

    bool IsInITBlock() const {
        return Mask() != 0b0000;
    }

    bool IsLastInITBlock() const {
        return Mask() == 0b1000;
    }

    ITState Advance() const {
        // Advance advances the IT state to the next row of the below table
        //
        // Instructions
        // Left in Block   value[7:5] [4] [3] [2] [1] [0]
        //
        //      4          cond_base   x   x   x   x   1
        //      3          cond_base   x   x   x   1   0
        //      2          cond_base   x   x   1   0   0
        //      1          cond_base   x   1   0   0   0
        //      0             000      0   0   0   0   0
        //
        //
        // NOTE: cond_base is the upper 3 bits of cond!
        //       In other words, cond == cond_base:value[4].
        //
        if (!IsInITBlock() || IsLastInITBlock()) {
            return ITState{};
        }
        return ITState{Common::ModifyBits<0, 4>(value, static_cast<u8>(value << 1))};
    }

    u8 Value() const {
        return value;
    }

private:
    u8 value = 0;
};

inline bool operator==(ITState lhs, ITState rhs) {
    return lhs.Value() == rhs.Value();
}

inline bool operator!=(ITState lhs, ITState rhs) {
    return !operator==(lhs, rhs);
}

} // namespace Dynarmic::A32

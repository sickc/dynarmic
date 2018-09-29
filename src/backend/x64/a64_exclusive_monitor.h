/* This file is part of the dynarmic project.
 * Copyright (c) 2018 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#pragma once

#include <dynarmic/A64/exclusive_monitor.h>
#include "common/common_types.h"

namespace Dynarmic::A64 {

struct ExclusiveMonitor::Impl {
    explicit Impl(size_t processor_count);

    size_t GetProcessorCount() const { return processor_count; }

    size_t processor_count;

    //
    // We assume an ERG of 64 bytes, which matches that declared by the Tegra X1.
    // The bits in `state` are arranged like so in memory:
    //
    //  64                         14  13 12                           0
    // +-----------------------------+---+------------------------------+
    // |           address           | L |       processor flags        |
    // +-----------------------------+---+------------------------------+
    //
    // address:         Bits 7-56 of the VAddr in currently marked.
    // processor flags: One flag per processor currently marking this address.
    //                  This implementation supports a maximum of 13 cores.
    // L:               Lock flag (is the state locked?)
    //
    u64 state = 0;
};

} // namespace Dynarmic::A64

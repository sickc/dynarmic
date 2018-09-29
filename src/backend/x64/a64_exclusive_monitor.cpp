/* This file is part of the dynarmic project.
 * Copyright (c) 2018 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#include <memory>

#include <dynarmic/A64/exclusive_monitor.h>
#include "backend/x64/a64_exclusive_monitor.h"
#include "common/assert.h"

namespace Dynarmic::A64 {

ExclusiveMonitor::ExclusiveMonitor(size_t processor_count) : impl(std::make_unique<ExclusiveMonitor::Impl>(processor_count)) {}

ExclusiveMonitor::~ExclusiveMonitor() = default;

size_t ExclusiveMonitor::GetProcessorCount() const {
    return impl->GetProcessorCount();
}

ExclusiveMonitor::Impl::Impl(size_t processor_count) : processor_count(processor_count) {
    ASSERT(processor_count <= 12);
}

} // namespace Dynarmic::A64

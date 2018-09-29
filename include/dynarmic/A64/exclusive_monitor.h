/* This file is part of the dynarmic project.
 * Copyright (c) 2018 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#pragma once

#include <cstddef>
#include <memory>

namespace Dynarmic {
namespace BackendX64 {
class A64EmitX64;
} // namespace BackendX64
} // namespace Dynarmic

namespace Dynarmic {
namespace A64 {

class ExclusiveMonitor {
public:
    /// @param processor_count Maximum number of processors using this global
    ///                        exclusive monitor. Each processor must have a
    ///                        unique id.
    ///                        Note that there may be a backend-specific limit
    ///                        to how many processors you can have.
    explicit ExclusiveMonitor(size_t processor_count);

    ~ExclusiveMonitor();

    size_t GetProcessorCount() const;

private:
    friend class Dynarmic::BackendX64::A64EmitX64;

    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace A64
} // namespace Dynarmic

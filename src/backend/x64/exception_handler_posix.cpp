/* This file is part of the dynarmic project.
 * Copyright (c) 2019 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

// Copyright 2008 Dolphin Emulator Project
// Licensed under GPLv2+
// Refer to the license.txt file included.

#include "backend/x64/exception_handler.h"

#include <cstring>
#include <memory>
#include <mutex>
#include <vector>

#include <signal.h>
#ifdef __APPLE__
#include <sys/ucontext.h>
#else
#include <ucontext.h>
#endif

#include "backend/x64/block_of_code.h"
#include "common/assert.h"
#include "common/cast_util.h"
#include "common/common_types.h"

namespace Dynarmic::BackendX64 {

namespace {

struct CodeBlockInfo {
    u64 code_begin, code_end;
    u64 thunk_address;
};

class SigHandler {
public:
    SigHandler();
    ~SigHandler();

    void AddCodeBlock(CodeBlockInfo info);
    void RemoveCodeBlock(u64 rip);

private:
    auto FindCodeBlockInfo(u64 rip) {
        return std::find_if(code_block_infos.begin(), code_block_infos.end(), [&](const auto& x) { return x.code_begin <= rip && x.code_end > rip; });
    }

    std::vector<CodeBlockInfo> code_block_infos;
    std::mutex code_block_infos_mutex;

    struct sigaction old_sa_segv;
    struct sigaction old_sa_bus;

    static void SigAction(int sig, siginfo_t* info, void* raw_context);
};

SigHandler sig_handler;

SigHandler::SigHandler() {
    // Method below from dolphin.

    constexpr size_t signal_stack_size = std::max(SIGSTKSZ, 2 * 1024 * 1024);

    stack_t signal_stack;
    signal_stack.ss_sp = malloc(signal_stack_size);
    signal_stack.ss_size = signal_stack_size;
    signal_stack.ss_flags = 0;
    ASSERT_MSG(sigaltstack(&signal_stack, nullptr) == 0, "dynarmic: POSIX SigHandler: init failure at sigaltstack");

    struct sigaction sa;
    sa.sa_handler = nullptr;
    sa.sa_sigaction = &SigHandler::SigAction;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &old_sa_segv);
#ifdef __APPLE__
    sigaction(SIGBUS, &sa, &old_sa_bus);
#endif
}

SigHandler::~SigHandler() {
    // No cleanup required.
}

void SigHandler::AddCodeBlock(CodeBlockInfo cbi) {
    std::lock_guard<std::mutex> guard(code_block_infos_mutex);
    ASSERT(FindCodeBlockInfo(cbi.code_begin) == code_block_infos.end());
    code_block_infos.push_back(cbi);
}

void SigHandler::RemoveCodeBlock(u64 rip) {
    std::lock_guard<std::mutex> guard(code_block_infos_mutex);
    const auto iter = FindCodeBlockInfo(rip);
    ASSERT(iter != code_block_infos.end());
    code_block_infos.erase(iter);
}

void SigHandler::SigAction(int sig, siginfo_t* info, void* raw_context) {
    ASSERT(sig == SIGSEGV || sig == SIGBUS);

#if defined(__APPLE__)
    #define CTX_RIP (((ucontext_t*)raw_context)->uc_mcontext->__ss.__rip)
    #define CTX_RAX (((ucontext_t*)raw_context)->uc_mcontext->__ss.__rax)
#elif defined(__linux__)
    #define CTX_RIP (((ucontext_t*)raw_context)->uc_mcontext.gregs[REG_RIP])
    #define CTX_RAX (((ucontext_t*)raw_context)->uc_mcontext.gregs[REG_RAX])
#elif defined(__FreeBSD__)
    #define CTX_RIP (((ucontext_t*)raw_context)->uc_mcontext.mc_rip)
    #define CTX_RAX (((ucontext_t*)raw_context)->uc_mcontext.mc_rax)
#else
    #error "Unknown platform"
#endif

    std::lock_guard<std::mutex> guard(sig_handler.code_block_infos_mutex);

    const auto iter = sig_handler.FindCodeBlockInfo(CTX_RIP);
    if (iter != sig_handler.code_block_infos.end()) {
        CTX_RAX = CTX_RIP;
        CTX_RIP = iter->thunk_address;

        return;
    }

    fmt::print(stderr, "dynarmic: POSIX SigHandler: Exception was not in registered code blocks (rip {:#016x})\n", CTX_RIP);

    struct sigaction* retry_sa = sig == SIGSEGV ? &sig_handler.old_sa_segv : &sig_handler.old_sa_bus;
    if (retry_sa->sa_flags & SA_SIGINFO) {
      retry_sa->sa_sigaction(sig, info, raw_context);
      return;
    }
    if (retry_sa->sa_handler == SIG_DFL) {
      signal(sig, SIG_DFL);
      return;
    }
    if (retry_sa->sa_handler == SIG_IGN) {
      return;
    }
    retry_sa->sa_handler(sig);
}

} // anonymous namespace

struct ExceptionHandler::Impl final {
    Impl(BlockOfCode& code, std::unique_ptr<Callback> cb) {
        code_begin = Common::BitCast<u64>(code.getCode());

        code.align(16);
        const u64 thunk = code.getCurr<u64>();
        code.push(code.rax);
        code.sub(code.rsp, sizeof(u64));
        code.pushf();
        code.sub(code.rsp, sizeof(X64State) - sizeof(u64));
        for (int i = 0; i < 16; i++) {
            if (i == 4) {
                continue; // Skip rsp
            }
            code.mov(code.qword[code.rsp + offsetof(X64State, gpr) + i * sizeof(u64)], Xbyak::Reg64(i));
        }
        for (int i = 0; i < 16; i++) {
            code.movaps(code.xword[code.rsp + offsetof(X64State, xmm) + i * sizeof(X64State::Vector)], Xbyak::Xmm(i));
        }
        code.mov(code.rax, code.qword[code.rsp + sizeof(X64State) + sizeof(u64)]);
        code.mov(code.qword[code.rsp + offsetof(X64State, rip)], code.rax);
        cb->EmitCall(code, [&](RegList param) {
            code.mov(param[0], code.rsp);
            static_assert(sizeof(X64State) % 16 == 0, "Will need to adjust rsp otherwise");
        });
        code.mov(code.rax, code.qword[code.rsp + offsetof(X64State, rip)]);
        code.mov(code.qword[code.rsp + sizeof(X64State) + sizeof(u64)], code.rax);
        for (int i = 0; i < 16; i++) {
            if (i == 4) {
                continue; // Skip rsp
            }
            code.mov(Xbyak::Reg64(i), code.qword[code.rsp + offsetof(X64State, gpr) + i * sizeof(u64)]);
        }
        for (int i = 0; i < 16; i++) {
            code.movaps(Xbyak::Xmm(i), code.xword[code.rsp + offsetof(X64State, xmm) + i * sizeof(X64State::Vector)]);
        }
        code.add(code.rsp, sizeof(X64State) - sizeof(u64));
        code.popf();
        code.add(code.rsp, sizeof(u64));
        code.ret();

        CodeBlockInfo cbi;
        cbi.code_begin = code_begin;
        cbi.code_end = code_begin + code.GetTotalCodeSize();
        cbi.thunk_address = thunk;
        sig_handler.AddCodeBlock(cbi);
    }

    ~Impl() {
        sig_handler.RemoveCodeBlock(code_begin);
    }

private:
    u64 code_begin;
};

ExceptionHandler::ExceptionHandler() = default;
ExceptionHandler::~ExceptionHandler() = default;

void ExceptionHandler::Register(BlockOfCode& code, std::unique_ptr<Callback> cb) {
    if (!cb) {
        return;
    }
    impl = std::make_unique<Impl>(code, std::move(cb));
}

bool ExceptionHandler::SupportsFastMem() const {
    return static_cast<bool>(impl);
}

} // namespace Dynarmic::BackendX64

/* This file is part of the dynarmic project.
 * Copyright (c) 2017 MerryMage
 * This software may be used and distributed according to the terms of the GNU
 * General Public License version 2 or any later version.
 */

#include <map>
#include <memory>
#include <thread>

#include <mach/mach.h>
#include <mach/message.h>

#include "backend_x64/block_of_code.h"
#include "backend_x64/parse_mov.h"
#include "common/assert.h"
#include "common/common_types.h"

#define mig_external extern "C"
#include "backend_x64/mig/mach_exc_server.h"

namespace Dynarmic {
namespace BackendX64 {

struct ExceptionHandlerInfo {
    u64 code_start;
    u64 code_end;
    u64 thunk_address;
};

static bool initialized = false;
static size_t init_count = 0;
static std::unique_ptr<std::thread> exception_thread;
static mach_port_t server_port;
static std::mutex exception_handler_info_mutex;
static std::map<u64, ExceptionHandlerInfo> exception_handler_info;

struct MachMessage {
    mach_msg_header_t head;
    char data[2048]; ///< Arbitrary size
};

static void ExceptionHandler() {
    mach_msg_return_t mr;
    MachMessage request;
    MachMessage reply;

    while (true) {
        mr = mach_msg(&request.head, MACH_RCV_MSG | MACH_RCV_LARGE, 0, sizeof(request), server_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (mr != MACH_MSG_SUCCESS) {
            fprintf(stderr, "dynarmic: macOS ExceptionHandler: Failed to receive mach message. error: %#08x (%s)", mr, mach_error_string(mr));
            return;
        }

        if (!mach_exc_server(&request.head, &reply.head)){
            fprintf(stderr, "dynarmic: Unexpected mach message\n");
            return;
        }

        mr = mach_msg(&reply.head, MACH_SEND_MSG, reply.head.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (mr != MACH_MSG_SUCCESS){
            fprintf(stderr, "dynarmic: macOS ExceptionHandler: Failed to send mach message. error: %#08x (%s)", mr, mach_error_string(mr));
            return;
        }
    }
}

mig_external kern_return_t catch_mach_exception_raise(mach_port_t, mach_port_t, mach_port_t, exception_type_t, mach_exception_data_t, mach_msg_type_number_t) {
    fprintf(stderr, "dynarmic: Unexpected mach message: mach_exception_raise\n");
    return KERN_FAILURE;
}

mig_external kern_return_t catch_mach_exception_raise_state_identity(mach_port_t, mach_port_t, mach_port_t, exception_type_t, mach_exception_data_t, mach_msg_type_number_t, int*, thread_state_t, mach_msg_type_number_t, thread_state_t, mach_msg_type_number_t*) {
    fprintf(stderr, "dynarmic: Unexpected mach message: mach_exception_raise_state_identity\n");
    return KERN_FAILURE;
}

mig_external kern_return_t catch_mach_exception_raise_state(
    mach_port_t /*exception_port*/,
    exception_type_t exception,
    const mach_exception_data_t /*code*/, // code[0] is as per kern_return.h, code[1] is rip.
    mach_msg_type_number_t /*codeCnt*/,
    int* flavor,
    const thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t* new_stateCnt
) {
    if (!flavor || !new_stateCnt) {
        fprintf(stderr, "dynarmic: catch_mach_exception_raise_state: Invalid arguments.\n");
        return KERN_INVALID_ARGUMENT;
    }
    if (*flavor != x86_THREAD_STATE64 || old_stateCnt != x86_THREAD_STATE64_COUNT || *new_stateCnt < x86_THREAD_STATE64_COUNT) {
        fprintf(stderr, "dynarmic: catch_mach_exception_raise_state: Unexpected flavor.\n");
        return KERN_INVALID_ARGUMENT;
    }
    if (exception != EXC_BAD_ACCESS) {
        fprintf(stderr, "dynarmic: catch_mach_exception_raise_state: Unexpected exception type.\n");
        return KERN_INVALID_ARGUMENT;
    }

    x86_thread_state64_t* x64_state = reinterpret_cast<x86_thread_state64_t*>(new_state);
    *x64_state = *reinterpret_cast<const x86_thread_state64_t*>(old_state);
    *new_stateCnt = x86_THREAD_STATE64_COUNT;

    std::lock_guard<std::mutex> guard(exception_handler_info_mutex);

    // Get exception handler information
    auto iter = exception_handler_info.upper_bound(x64_state->__rip);
    if (iter == exception_handler_info.begin()) {
        fprintf(stderr, "dynarmic: catch_mach_exception_raise_state: Exception was not in JITted code [1](rip 0x%08llx)\n", x64_state->__rip);
        return KERN_FAILURE;
    }
    --iter;
    if (iter->second.code_start > x64_state->__rip && x64_state->__rip <= iter->second.code_end) {
        fprintf(stderr, "dynarmic: catch_mach_exception_raise_state: Exception was not in JITted code [2](rip 0x%08llx)\n", x64_state->__rip);
        return KERN_FAILURE;
    }

    // fprintf(stderr, "rip 0x%08llx\n", x64_state->__rip);

    x64_state->__rsp -= sizeof(u64);
    *reinterpret_cast<u64*>(x64_state->__rsp) = x64_state->__rip;
    x64_state->__rip = iter->second.thunk_address;

    return KERN_SUCCESS;
}

static void Init() {
    if (init_count++ > 0)
        return;
    if (initialized)
        return;

    #define KCHECK(x) if ((x) != KERN_SUCCESS) { printf("fastmem init failure at %s\n", #x); return; }
    KCHECK(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &server_port));
    KCHECK(mach_port_insert_right(mach_task_self(), server_port, server_port, MACH_MSG_TYPE_MAKE_SEND));
    KCHECK(task_set_exception_ports(mach_task_self(), EXC_MASK_BAD_ACCESS, server_port, EXCEPTION_STATE | MACH_EXCEPTION_CODES, x86_THREAD_STATE64));
    #undef KCHECK

    if (!initialized)
        exception_thread = std::make_unique<std::thread>(ExceptionHandler);

    initialized = true;
}

static void Deinit() {
    ASSERT(init_count != 0);
    if (--init_count > 0)
        return;
    if (!initialized)
        return;

    //exception_thread.reset();
    //mach_port_destroy(mach_task_self(), server_port);

    //initialized = false;
}

struct X64RegisterState {
    u64 gpr[16];
    u64 xmm[16];
    u64 rip;
    u64 rflags;
};

struct BlockOfCode::ExceptionHandler::Impl final {
    u64 code_start;
    BlockOfCode* code;
    UserCallbacks cb;
    std::function<void(const u8*)> invalidate_block;

    static void Callback(BlockOfCode::ExceptionHandler::Impl* impl, X64RegisterState* reg_state) {
        auto inst = ParseX64MemoryMovInstruction(reinterpret_cast<const u8*>(reg_state->rip));
        ASSERT_MSG(inst, "Not a parseable mov instruction!");

        ASSERT(inst->displacement == 0);
        ASSERT(inst->scale == 1);

        size_t mem_vaddr_reg;
        if (impl->cb.fast_mem_base) {
            ASSERT(!(inst->index == 14 && inst->base == 14));
            mem_vaddr_reg = inst->index == 14 ? inst->base : inst->index;
        } else {
            mem_vaddr_reg = impl->code->ABI_PARAM1.getIdx();
        }

        if (inst->is_write) {
            u64 src = reg_state->gpr[inst->reg];
            u32 vaddr = static_cast<u32>(reg_state->gpr[mem_vaddr_reg]);
            switch (inst->bit_size) {
            case 8:
                impl->cb.memory.Write8(vaddr, static_cast<u8>(src));
                break;
            case 16:
                impl->cb.memory.Write16(vaddr, static_cast<u16>(src));
                break;
            case 32:
                impl->cb.memory.Write32(vaddr, static_cast<u32>(src));
                break;
            case 64:
                impl->cb.memory.Write64(vaddr, src);
                break;
            default:
                ASSERT_MSG(false, "Unreachable");
                return;
            }
        } else {
            u64& dest = reg_state->gpr[inst->reg];
            u32 vaddr = static_cast<u32>(reg_state->gpr[mem_vaddr_reg]);
            switch (inst->bit_size) {
            case 8:
                dest = impl->cb.memory.Read8(vaddr);
                break;
            case 16:
                dest = impl->cb.memory.Read16(vaddr);
                break;
            case 32:
                dest = impl->cb.memory.Read32(vaddr);
                break;
            case 64:
                dest = impl->cb.memory.Read64(vaddr);
                break;
            default:
                ASSERT_MSG(false, "Unreachable");
                return;
            }
        }

        impl->invalidate_block(reinterpret_cast<const u8*>(reg_state->rip));
        // printf("%llx -> %llx\n", reg_state->rip, reinterpret_cast<u64>(inst->next_instruction));
        reg_state->rip = reinterpret_cast<u64>(inst->next_instruction);
    }
};

BlockOfCode::ExceptionHandler::ExceptionHandler() {
    Init();
}
BlockOfCode::ExceptionHandler::~ExceptionHandler() {
    std::lock_guard<std::mutex> guard(exception_handler_info_mutex);
    exception_handler_info.clear();
    Deinit();
}

void BlockOfCode::ExceptionHandler::Register(BlockOfCode* code, const UserCallbacks& cb) {
    impl = std::make_unique<Impl>();
    impl->code = code;
    impl->cb = cb;
    impl->code_start = reinterpret_cast<u64>(code->top_);

    using namespace Xbyak::util;

    code->align(16);
    const u8* thunk_function = code->getCurr();

    code->pushf();
    code->sub(code->rsp, sizeof(X64RegisterState) - sizeof(u64));
    code->mov(code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 0 * sizeof(u64)], code->rax);
    code->mov(code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 1 * sizeof(u64)], code->rcx);
    code->mov(code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 2 * sizeof(u64)], code->rdx);
    code->mov(code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 3 * sizeof(u64)], code->rbx);
    // Skipping rsp
    code->mov(code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 5 * sizeof(u64)], code->rbp);
    code->mov(code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 6 * sizeof(u64)], code->rsi);
    code->mov(code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 7 * sizeof(u64)], code->rdi);
    code->mov(code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 8 * sizeof(u64)], code->r8);
    code->mov(code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 9 * sizeof(u64)], code->r9);
    code->mov(code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 10 * sizeof(u64)], code->r10);
    code->mov(code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 11 * sizeof(u64)], code->r11);
    code->mov(code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 12 * sizeof(u64)], code->r12);
    code->mov(code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 13 * sizeof(u64)], code->r13);
    code->mov(code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 14 * sizeof(u64)], code->r14);
    code->mov(code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 15 * sizeof(u64)], code->r15);
    code->movq(code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 0 * sizeof(u64)], code->xmm0);
    code->movq(code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 1 * sizeof(u64)], code->xmm1);
    code->movq(code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 2 * sizeof(u64)], code->xmm2);
    code->movq(code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 3 * sizeof(u64)], code->xmm3);
    code->movq(code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 4 * sizeof(u64)], code->xmm4);
    code->movq(code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 5 * sizeof(u64)], code->xmm5);
    code->movq(code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 6 * sizeof(u64)], code->xmm6);
    code->movq(code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 7 * sizeof(u64)], code->xmm7);
    code->movq(code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 8 * sizeof(u64)], code->xmm8);
    code->movq(code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 9 * sizeof(u64)], code->xmm9);
    code->movq(code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 10 * sizeof(u64)], code->xmm10);
    code->movq(code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 11 * sizeof(u64)], code->xmm11);
    code->movq(code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 12 * sizeof(u64)], code->xmm12);
    code->movq(code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 13 * sizeof(u64)], code->xmm13);
    code->movq(code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 14 * sizeof(u64)], code->xmm14);
    code->movq(code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 15 * sizeof(u64)], code->xmm15);
    code->mov(code->rax, code->qword[code->rsp + sizeof(X64RegisterState)]);
    code->mov(code->qword[code->rsp + offsetof(X64RegisterState, rip)], code->rax);
    code->mov(code->ABI_PARAM2, code->rsp);
    code->sub(code->rsp, 8 + (sizeof(X64RegisterState) % 16));
    code->mov(code->ABI_PARAM1, reinterpret_cast<u64>(impl.get()));
    code->CallFunction(&BlockOfCode::ExceptionHandler::Impl::Callback);
    code->add(code->rsp, 8 + (sizeof(X64RegisterState) % 16));
    code->mov(code->rax, code->qword[code->rsp + offsetof(X64RegisterState, rip)]);
    code->mov(code->qword[code->rsp + sizeof(X64RegisterState)], code->rax);
    code->mov(code->rax, code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 0 * sizeof(u64)]);
    code->mov(code->rcx, code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 1 * sizeof(u64)]);
    code->mov(code->rdx, code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 2 * sizeof(u64)]);
    code->mov(code->rbx, code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 3 * sizeof(u64)]);
    // Skipping rsp
    code->mov(code->rbp, code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 5 * sizeof(u64)]);
    code->mov(code->rsi, code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 6 * sizeof(u64)]);
    code->mov(code->rdi, code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 7 * sizeof(u64)]);
    code->mov(code->r8, code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 8 * sizeof(u64)]);
    code->mov(code->r9, code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 9 * sizeof(u64)]);
    code->mov(code->r10, code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 10 * sizeof(u64)]);
    code->mov(code->r11, code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 11 * sizeof(u64)]);
    code->mov(code->r12, code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 12 * sizeof(u64)]);
    code->mov(code->r13, code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 13 * sizeof(u64)]);
    code->mov(code->r14, code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 14 * sizeof(u64)]);
    code->mov(code->r15, code->qword[code->rsp + offsetof(X64RegisterState, gpr) + 15 * sizeof(u64)]);
    code->movq(code->xmm0, code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 0 * sizeof(u64)]);
    code->movq(code->xmm1, code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 1 * sizeof(u64)]);
    code->movq(code->xmm2, code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 2 * sizeof(u64)]);
    code->movq(code->xmm3, code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 3 * sizeof(u64)]);
    code->movq(code->xmm4, code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 4 * sizeof(u64)]);
    code->movq(code->xmm5, code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 5 * sizeof(u64)]);
    code->movq(code->xmm6, code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 6 * sizeof(u64)]);
    code->movq(code->xmm7, code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 7 * sizeof(u64)]);
    code->movq(code->xmm8, code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 8 * sizeof(u64)]);
    code->movq(code->xmm9, code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 9 * sizeof(u64)]);
    code->movq(code->xmm10, code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 10 * sizeof(u64)]);
    code->movq(code->xmm11, code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 11 * sizeof(u64)]);
    code->movq(code->xmm12, code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 12 * sizeof(u64)]);
    code->movq(code->xmm13, code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 13 * sizeof(u64)]);
    code->movq(code->xmm14, code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 14 * sizeof(u64)]);
    code->movq(code->xmm15, code->qword[code->rsp + offsetof(X64RegisterState, xmm) + 15 * sizeof(u64)]);
    code->add(code->rsp, sizeof(X64RegisterState) - sizeof(u64));
    code->popf();
    code->ret();

    std::lock_guard<std::mutex> guard(exception_handler_info_mutex);
    exception_handler_info[impl->code_start] = {
        impl->code_start,
        reinterpret_cast<u64>(code->top_ + code->maxSize_),
        reinterpret_cast<u64>(thunk_function)
    };
}

bool BlockOfCode::ExceptionHandler::SupportsFastMem() const {
    return initialized;
}

void BlockOfCode::ExceptionHandler::SetFastMemCallback(std::function<void(const u8*)> invalidate_block) {
    impl->invalidate_block = invalidate_block;
}

} // namespace BackendX64
} // namespace Dynarmic
